const mongoose = require('mongoose');

const urlSchema = new mongoose.Schema({
  originalUrl: {
    type: String,
    required: true
  },
  shortUrl: {
    type: String,
    required: true
  },
  urlId: {
    type: String,
    required: true,
    unique: true
  },
  customSlug: {
    type: String,
    unique: true,
    sparse: true,
    default: undefined
  },
  title: {
    type: String,
    default: ''
  },
  description: {
    type: String,
    default: ''
  },
  clicks: {
    type: Number,
    default: 0
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: function() {
      return this.isUserLink !== false;
    }
  },
  isUserLink: {
    type: Boolean,
    default: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  expiresAt: {
    type: Date,
    default: null
  },
  password: {
    type: String,
    default: null
  },
  clickHistory: [{
    timestamp: Date,
    ip: String,
    userAgent: String,
    referer: String
  }],
  tags: [String],
  lastAccessed: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Index để tìm kiếm nhanh
urlSchema.index({ userId: 1, createdAt: -1 });
urlSchema.index({ urlId: 1 });

urlSchema.pre('save', function(next){
  if(this.customSlug === null|| this.customSlug === ''){
    this.customSlug = undefined
  }
  next();
})

module.exports = mongoose.model('Url', urlSchema);