// Example using Mongoose for MongoDB
const mongoose = require("mongoose");
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },

  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,

    // Not required if logging in via Google
    // You might set a default placeholder or leave null if only Google login is allowed
    sparse: true, // Allows nulls, enabling Google users to not have a password
  },
  googleId: {
    // New field for Google's unique ID
    type: String,
    unique: true,
    sparse: true, // Allows nulls for non-Google users
  },
  // New fields for "Forgot Password"
  passwordResetToken: {
    type: String,
    default: null,
  },
  passwordResetExpires: {
    type: Date,
    default: null,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});
module.exports = mongoose.model("User", userSchema);
