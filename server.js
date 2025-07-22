require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const validUrl = require('valid-url');
const shortid = require('shortid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Url = require('./models/Url');
const User = require('./models/User');
const { auth, optionalAuth, adminAuth } = require('./middleware/auth');

const app = express();

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Kết nối MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Đã kết nối MongoDB'))
  .catch(err => console.error('Lỗi kết nối MongoDB:', err));

// Route trang chủ
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});
// Route trang chủ
app.get('/admin', (req, res) => {
  res.sendFile(__dirname + '/public/admin.html');
});
// Route trang chủ
app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});
// Route đăng ký
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, fullName } = req.body;

    // Kiểm tra user đã tồn tại
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email hoặc username đã tồn tại'
      });
    }

    // Tạo user mới
    const user = new User({
      username,
      email,
      password,
      fullName
    });

    await user.save();

    // Tạo JWT token
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      message: 'Đăng ký thành công',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        plan: user.plan,
        linkCount: user.linkCount,
        maxLinks: user.maxLinks
      }
    });

  } catch (error) {
    console.error('Lỗi đăng ký:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});

// Route đăng nhập
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Tìm user
    const user = await User.findOne({
      $or: [{ email: username }, { username }]
    });

    if (!user || !user.isActive) {
      return res.status(400).json({
        success: false,
        message: 'Thông tin đăng nhập không chính xác'
      });
    }

    // Kiểm tra password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Thông tin đăng nhập không chính xác'
      });
    }

    // Tạo JWT token
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Set cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      message: 'Đăng nhập thành công',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        plan: user.plan,
        linkCount: user.linkCount,
        maxLinks: user.maxLinks
      }
    });

  } catch (error) {
    console.error('Lỗi đăng nhập:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});
// Route đăng nhập admin
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Tìm user admin theo username hoặc email
    const adminUser = await User.findOne({
      $or: [{ email: username }, { username }],
     role: 'admin'
    });

    if (!adminUser || !adminUser.isActive) {
      return res.status(400).json({
        success: false,
        message: 'Thông tin đăng nhập admin không chính xác'
      });
    }

    // So sánh password
    const isMatch = await adminUser.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Thông tin đăng nhập admin không chính xác'
      });
    }

    // Tạo JWT token cho admin
    const token = jwt.sign(
      { id: adminUser._id, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Set cookie cho admin
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 ngày
    });

    res.json({
      success: true,
      message: 'Đăng nhập admin thành công',
      user: {
        id: adminUser._id,
        username: adminUser.username,
        email: adminUser.email,
        fullName: adminUser.fullName,
        role: 'admin'
      }
    });
  } catch (error) {
    console.error('Lỗi đăng nhập admin:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});
// Route đăng xuất
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({
    success: true,
    message: 'Đăng xuất thành công'
  });
});

// Route lấy thông tin user hiện tại
app.get('/api/me', auth, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      fullName: req.user.fullName,
      role: req.user.role,
      plan: req.user.plan,
      linkCount: req.user.linkCount,
      maxLinks: req.user.maxLinks
    }
  });
});

// Route nâng cấp premium
app.post('/api/upgrade-premium', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    user.plan = 'premium';
    await user.save();

    res.json({
      success: true,
      message: 'Nâng cấp Premium thành công!',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        plan: user.plan,
        linkCount: user.linkCount,
        maxLinks: user.maxLinks
      }
    });
  } catch (error) {
    console.error('Lỗi nâng cấp:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});
// ADMIN: Lấy danh sách tất cả users
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json({ success: true, data: users });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// ADMIN: Cập nhật thông tin user
app.put('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    // Nếu thay đổi plan, maxLinks sẽ được cập nhật tự động bởi pre-save
  const user = await User.findById(id);
if (!user) {
  return res.status(404).json({ success: false, message: 'User không tồn tại' });
}

Object.assign(user, updates); // cập nhật các field từ req.body
await user.save(); // sẽ kích hoạt pre('save')

res.json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// ADMIN: Đổi mật khẩu cho user
app.post('/api/admin/users/:id/change-password', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'Mật khẩu phải có ít nhất 6 ký tự' });
    }

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ success: false, message: 'User không tồn tại' });

    user.password = newPassword;
    await user.save();

    res.json({ success: true, message: 'Đổi mật khẩu thành công' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});

// ADMIN: Lấy danh sách link của 1 user
app.get('/api/admin/users/:id/links', adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const urls = await Url.find({ userId: id }).sort({ createdAt: -1 });

    res.json({ success: true, data: urls });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Lỗi server' });
  }
});
// Function tạo random slug
function generateRandomSlug(length = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// API tạo link rút gọn - CHỈ PREMIUM
app.post('/api/shorten', auth, async (req, res) => {
  try {
    // Kiểm tra plan premium
    if (req.user.plan !== 'premium') {
      return res.status(403).json({
        success: false,
        message: 'Chỉ tài khoản Premium mới có thể rút gọn link. Vui lòng nâng cấp!'
      });
    }

    const { originalUrl, customSlug, useRandomSlug } = req.body;
    const baseUrl = process.env.BASE_URL;

    // Kiểm tra URL hợp lệ
    if (!validUrl.isUri(originalUrl)) {
      return res.status(400).json({ 
        success: false, 
        message: 'URL không hợp lệ' 
      });
    }

    // Kiểm tra giới hạn link
    if (req.user.linkCount >= req.user.maxLinks) {
      return res.status(400).json({
        success: false,
        message: 'Đã đạt giới hạn số lượng link'
      });
    }

    

    let urlId;
    let finalSlug;

    // Xử lý slug
    if (useRandomSlug) {
      // Tạo random slug
      do {
        urlId = generateRandomSlug(8);
        const existingSlug = await Url.findOne({ urlId });
        if (!existingSlug) break;
      } while (true);
      console.log(urlId);
      
      // FIX: Không set customSlug cho random slug
      finalSlug = undefined; // Hoặc bỏ qua field này hoàn toàn
    } else if (customSlug) {
      // Xử lý custom slug
      if (!/^[a-zA-Z0-9-_]+$/.test(customSlug)) {
        return res.status(400).json({
          success: false,
          message: 'Slug chỉ được chứa chữ cái, số, dấu gạch ngang và gạch dưới'
        });
      }

      // Kiểm tra slug đã tồn tại chưa
      const existingSlug = await Url.findOne({ urlId: customSlug });
      if (existingSlug) {
        return res.status(400).json({
          success: false,
          message: 'Slug này đã được sử dụng'
        });
      }

      urlId = customSlug;
      finalSlug = customSlug;
    } else {
      // Tạo ID ngẫu nhiên mặc định
      urlId = shortid.generate();
      finalSlug = undefined; // FIX: Không set customSlug cho shortid
    }

    const shortUrl = `${baseUrl}/${urlId}`;
    console.log(shortUrl);

    // Tạo record mới - chỉ include customSlug khi có giá trị
    const urlData = {
      originalUrl,
      shortUrl,
      urlId,
      userId: req.user._id
    };

    // Chỉ thêm customSlug khi có giá trị thực sự
    if (finalSlug) {
      urlData.customSlug = finalSlug;
    }

    const newUrl = new Url(urlData);
    await newUrl.save();

    // Cập nhật số lượng link của user
    await User.findByIdAndUpdate(req.user._id, {
      $inc: { linkCount: 1 }
    });

    res.json({
      success: true,
      data: {
        originalUrl: newUrl.originalUrl,
        shortUrl: newUrl.shortUrl,
        urlId: newUrl.urlId,
        customSlug: newUrl.customSlug,
        clicks: newUrl.clicks,
        createdAt: newUrl.createdAt
      }
    });

  } catch (error) {
    console.error('Lỗi tạo link rút gọn:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});

// API cập nhật custom slug
app.put('/api/update-slug/:urlId', auth, async (req, res) => {
  try {
    const { urlId } = req.params;
    const { newSlug } = req.body;

    if (!newSlug) {
      return res.status(400).json({
        success: false,
        message: 'Vui lòng nhập slug mới'
      });
    }

    // Kiểm tra slug hợp lệ
    if (!/^[a-zA-Z0-9-_]+$/.test(newSlug)) {
      return res.status(400).json({
        success: false,
        message: 'Slug chỉ được chứa chữ cái, số, dấu gạch ngang và gạch dưới'
      });
    }

    // Kiểm tra slug đã tồn tại chưa
    const existingSlug = await Url.findOne({ urlId: newSlug });
    if (existingSlug && existingSlug.urlId !== urlId) {
      return res.status(400).json({
        success: false,
        message: 'Slug này đã được sử dụng'
      });
    }

    // Tìm và cập nhật URL của user
    const url = await Url.findOne({ urlId, userId: req.user._id });
    if (!url) {
      return res.status(404).json({
        success: false,
        message: 'Không tìm thấy URL hoặc bạn không có quyền sửa'
      });
    }

    url.customSlug = newSlug;
    url.urlId = newSlug;
    url.shortUrl = `${process.env.BASE_URL}/${newSlug}`;
    
    await url.save();

    res.json({
      success: true,
      data: {
        originalUrl: url.originalUrl,
        shortUrl: url.shortUrl,
        urlId: url.urlId,
        customSlug: url.customSlug,
        clicks: url.clicks,
        createdAt: url.createdAt
      }
    });

  } catch (error) {
    console.error('Lỗi cập nhật slug:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});

// API lấy danh sách URLs của user
app.get('/api/urls', auth, async (req, res) => {
  try {
    const urls = await Url.find({ userId: req.user._id })
      .sort({ createdAt: -1 });
    res.json({
      success: true,
      data: urls
    });
  } catch (error) {
    console.error('Lỗi lấy danh sách URLs:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});

// API lấy thống kê URL
app.get('/api/stats/:urlId', auth, async (req, res) => {
  try {
    const { urlId } = req.params;
    const url = await Url.findOne({ urlId, userId: req.user._id });
    
    if (!url) {
      return res.status(404).json({
        success: false,
        message: 'Không tìm thấy URL hoặc bạn không có quyền xem'
      });
    }

    res.json({
      success: true,
      data: {
        originalUrl: url.originalUrl,
        shortUrl: url.shortUrl,
        clicks: url.clicks,
        createdAt: url.createdAt,
        lastAccessed: url.lastAccessed
      }
    });
  } catch (error) {
    console.error('Lỗi lấy thống kê:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});

// Route redirect - không cần auth
app.get('/:urlId', async (req, res) => {
  try {
    const { urlId } = req.params;
    
    const url = await Url.findOne({ urlId });
    
    if (!url) {
      return res.status(404).json({
        success: false,
        message: 'URL không tồn tại'
      });
    }

    // Tăng số lượt click và cập nhật thời gian truy cập
    url.clicks++;
    url.lastAccessed = new Date();
    await url.save();

    // Redirect đến URL gốc
    res.redirect(url.originalUrl);
    
  } catch (error) {
    console.error('Lỗi redirect:', error);
    res.status(500).json({
      success: false,
      message: 'Lỗi server'
    });
  }
});

// Khởi động server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server đang chạy trên port ${PORT}`);
  console.log(`Truy cập: http://localhost:${PORT}`);
});
