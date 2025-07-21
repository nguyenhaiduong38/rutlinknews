const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  plan: {
    type: String,
    enum: ['free', 'premium'],
    default: 'free'
  },
  premiumExpiry: {
    type: Date,
    default: null
  },
  linkCount: {
    type: Number,  
    default: 0
  },
  maxLinks: {
    type: Number,
    default: 100 
  },
  resetPasswordToken: {
    type: String,
    default: undefined
  },
  resetPasswordExpire: {
    type: Date,
    default: undefined
  },
  emailVerificationToken: {
    type: String,
    default: undefined
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// Set maxLinks based on plan
userSchema.pre('save', function(next) {
  if (this.isModified('plan')) {
    this.maxLinks = this.plan === 'premium' ? 10000 : 100;
  }
  next();
});

// Hash password trước khi lưu
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// So sánh password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Tạo reset password token
userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  
  this.resetPasswordToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
    
  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 phút
  
  return resetToken;
};

// Tạo email verification token
userSchema.methods.createEmailVerificationToken = function() {
  const verificationToken = crypto.randomBytes(32).toString('hex');
  
  this.emailVerificationToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');
    
  return verificationToken;
};

// Check if premium is expired
userSchema.methods.checkPremiumExpiry = function() {
  if (this.plan === 'premium' && this.premiumExpiry && this.premiumExpiry < new Date()) {
    this.plan = 'free';
    this.maxLinks = 100;
    this.premiumExpiry = null;
    return true;
  }
  return false;
};

module.exports = mongoose.model('User', userSchema);