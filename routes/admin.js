const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Link = require('../models/Link');
const { adminAuth } = require('../middleware/auth');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Email transporter (configure based on your email service)
const createEmailTransporter = () => {
  return nodemailer.createTransporter({
    service: 'gmail', // or your email service
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD
    }
  });
};

// Admin login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Vui lòng nhập email và mật khẩu'
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user || user.role !== 'admin') {
      return res.status(401).json({
        success: false,
        message: 'Email hoặc mật khẩu không chính xác'
      });
    }

    if (!user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Tài khoản đã bị vô hiệu hóa'
      });
    }

    const isPasswordMatch = await user.comparePassword(password);
    if (!isPasswordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Email hoặc mật khẩu không chính xác'
      });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });

    res.json({
      success: true,
      message: 'Đăng nhập thành công',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});

// Get admin info
router.get('/me', adminAuth, async (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

// Get dashboard stats
router.get('/stats', adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({ role: 'user' });
    const premiumUsers = await User.countDocuments({ plan: 'premium', role: 'user' });
    const totalLinks = await Link.countDocuments();
    const totalClicks = await Link.aggregate([
      { $group: { _id: null, total: { $sum: '$clicks' } } }
    ]);

    res.json({
      success: true,
      stats: {
        totalUsers,
        premiumUsers,
        totalLinks,
        totalClicks: totalClicks[0]?.total || 0
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi lấy thống kê'
    });
  }
});

// Get users with pagination
router.get('/users', adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const users = await User.find({ role: 'user' })
      .select('-password -resetPasswordToken -emailVerificationToken')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalUsers = await User.countDocuments({ role: 'user' });
    const totalPages = Math.ceil(totalUsers / limit);

    res.json({
      success: true,
      users,
      pagination: {
        page,
        totalPages,
        totalUsers,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi lấy danh sách users'
    });
  }
});

// Create new user
router.post('/users', adminAuth, async (req, res) => {
  try {
    const { username, email, fullName, password, plan, isActive } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Username hoặc email đã tồn tại'
      });
    }

    const newUser = new User({
      username,
      email: email.toLowerCase(),
      fullName,
      password,
      plan: plan || 'free',
      isActive: isActive !== undefined ? isActive : true,
      isEmailVerified: true // Admin created users are auto-verified
    });

    await newUser.save();

    res.status(201).json({
      success: true,
      message: 'Tạo user thành công',
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        fullName: newUser.fullName,
        plan: newUser.plan,
        isActive: newUser.isActive
      }
    });

  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi tạo user'
    });
  }
});

// Update user
router.put('/users/:id', adminAuth, async (req, res) => {
  try {
    const { username, email, fullName, plan, isActive, password } = req.body;
    const userId = req.params.id;

    const user = await User.findById(userId);
    if (!user || user.role === 'admin') {
      return res.status(404).json({
        success: false,
        message: 'User không tồn tại'
      });
    }

    // Check for duplicate username/email (excluding current user)
    const existingUser = await User.findOne({
      $and: [
        { _id: { $ne: userId } },
        { $or: [{ username }, { email: email.toLowerCase() }] }
      ]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Username hoặc email đã tồn tại'
      });
    }

    // Update fields
    user.username = username;
    user.email = email.toLowerCase();
    user.fullName = fullName;
    user.plan = plan;
    user.isActive = isActive;

    if (password && password.trim() !== '') {
      user.password = password;
    }

    // Set premium expiry if upgrading to premium
    if (plan === 'premium' && user.plan !== 'premium') {
      user.premiumExpiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year
    }

    await user.save();

    res.json({
      success: true,
      message: 'Cập nhật user thành công'
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi cập nhật user'
    });
  }
});

// Toggle user plan
router.put('/users/:id/toggle-plan', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role === 'admin') {
      return res.status(404).json({
        success: false,
        message: 'User không tồn tại'
      });
    }

    if (user.plan === 'free') {
      user.plan = 'premium';
      user.premiumExpiry = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year
    } else {
      user.plan = 'free';
      user.premiumExpiry = null;
    }

    await user.save();

    res.json({
      success: true,
      message: `Đã ${user.plan === 'premium' ? 'nâng cấp lên Premium' : 'hạ xuống Free'} thành công`
    });

  } catch (error) {
    console.error('Toggle plan error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi cập nhật plan'
    });
  }
});

// Toggle user status
router.put('/users/:id/toggle-status', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role === 'admin') {
      return res.status(404).json({
        success: false,
        message: 'User không tồn tại'
      });
    }

    user.isActive = !user.isActive;
    await user.save();

    res.json({
      success: true,
      message: `Đã ${user.isActive ? 'kích hoạt' : 'vô hiệu hóa'} user thành công`
    });

  } catch (error) {
    console.error('Toggle status error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi cập nhật trạng thái'
    });
  }
});

// Reset user password
router.post('/users/:id/reset-password', adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role === 'admin') {
      return res.status(404).json({
        success: false,
        message: 'User không tồn tại'
      });
    }

    // Generate new temporary password
    const tempPassword = crypto.randomBytes(8).toString('hex');
    user.password = tempPassword;
    
    // Clear any existing reset tokens
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    
    await user.save();

    // Send email with new password
    try {
      const transporter = createEmailTransporter();
      
      await transporter.sendMail({
        from: process.env.FROM_EMAIL,
        to: user.email,
        subject: 'Mật khẩu mới - Admin Reset',
        html: `
          <h2>Mật khẩu đã được reset</h2>
          <p>Xin chào ${user.fullName},</p>
          <p>Mật khẩu của bạn đã được admin reset. Mật khẩu mới của bạn là:</p>
          <h3 style="background: #f0f0f0; padding: 10px; border-radius: 5px;">${tempPassword}</h3>
          <p>Vui lòng đăng nhập và đổi mật khẩu ngay lập tức.</p>
          <p>Nếu bạn không yêu cầu reset mật khẩu, vui lòng liên hệ admin ngay.</p>
        `
      });
    } catch (emailError) {
      console.error('Email send error:', emailError);
      // If email fails, still return success but mention email issue
      return res.json({
        success: true,
        message: 'Reset mật khẩu thành công. Mật khẩu mới: ' + tempPassword + ' (Không thể gửi email)',
        tempPassword
      });
    }

    res.json({
      success: true,
      message: 'Reset mật khẩu thành công. Mật khẩu mới đã được gửi qua email.'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi reset mật khẩu'
    });
  }
});

// Get links with pagination
router.get('/links', adminAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const links = await Link.find()
      .populate('userId', 'username email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const totalLinks = await Link.countDocuments();
    const totalPages = Math.ceil(totalLinks / limit);

    res.json({
      success: true,
      links,
      pagination: {
        page,
        totalPages,
        totalLinks,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Get links error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi lấy danh sách links'
    });
  }
});

// Toggle link status
router.put('/links/:id/toggle-status', adminAuth, async (req, res) => {
  try {
    const link = await Link.findById(req.params.id);
    if (!link) {
      return res.status(404).json({
        success: false,
        message: 'Link không tồn tại'
      });
    }

    link.isActive = !link.isActive;
    await link.save();

    res.json({
      success: true,
      message: `Đã ${link.isActive ? 'kích hoạt' : 'vô hiệu hóa'} link thành công`
    });

  } catch (error) {
    console.error('Toggle link status error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi cập nhật trạng thái link'
    });
  }
});

// Delete link
router.delete('/links/:id', adminAuth, async (req, res) => {
  try {
    const link = await Link.findById(req.params.id);
    if (!link) {
      return res.status(404).json({
        success: false,
        message: 'Link không tồn tại'
      });
    }

    // Update user's link count
    if (link.userId) {
      await User.findByIdAndUpdate(link.userId, {
        $inc: { linkCount: -1 }
      });
    }

    await Link.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: 'Xóa link thành công'
    });

  } catch (error) {
    console.error('Delete link error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi xóa link'
    });
  }
});

// Update system settings
router.put('/settings', adminAuth, async (req, res) => {
  try {
    const { freeLinkLimit, premiumLinkLimit } = req.body;

    // Update all free users
    await User.updateMany(
      { plan: 'free' },
      { maxLinks: freeLinkLimit }
    );

    // Update all premium users
    await User.updateMany(
      { plan: 'premium' },
      { maxLinks: premiumLinkLimit }
    );

    res.json({
      success: true,
      message: 'Cập nhật cài đặt thành công'
    });

  } catch (error) {
    console.error('Update settings error:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi cập nhật cài đặt'
    });
  }
});

module.exports = router;
