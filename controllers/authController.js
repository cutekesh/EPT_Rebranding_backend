// controllers/authController.js
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User"); // Your User model
const crypto = require("crypto"); // Built-in Node.js module
const { OAuth2Client } = require("google-auth-library"); // For Google OAuth
const nodemailer = require("nodemailer"); // For sending emails (replace with SendGrid/Mailgun for production)

// --- Nodemailer Setup (replace with your chosen email service) ---
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_PORT == 465, // Use true for 465, false for other ports like 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
// --- END Nodemailer Setup ---

// --- Google OAuth2Client Setup ---
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
// --- END Google OAuth2Client Setup ---

// Helper function to generate JWT
const generateToken = (userId, username) => {
  return jwt.sign({ userId, username }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
};

exports.signup = async (req, res) => {
  // ... (same signup logic as before)
  try {
    const { username, email, password } = req.body;
    // 1. Input Validation
    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res
        .status(409)
        .json({ message: "Username or email already exists." });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign(
      { userId: newUser._id, username: newUser.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(201).json({
      message: "User registered successfully!",
      token,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error during sign-up." });
  }
};

exports.login = async (req, res) => {
  // ... (same login logic as before)
  try {
    const { usernameOrEmail, password } = req.body;
    if (!usernameOrEmail || !password) {
      return res
        .status(400)
        .json({ message: "Username/Email and password are required." });
    }
    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }],
    });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials." });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials." });
    }
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Login successful!",
      token,
      user: { id: user._id, username: user.username, email: user.email },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error during login." });
  }
};

// Existing Protected Profile Controller (added here for consistency)
exports.getProfile = async (req, res) => {
  try {
    // req.user is set by the authenticateToken middleware
    const user = await User.findById(req.user.userId).select(
      "-password -passwordResetToken -passwordResetExpires"
    );
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }
    res.status(200).json({
      message: `Welcome, ${
        user.username || user.email
      }! This is protected data.`,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        googleId: user.googleId, // Include googleId if present
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error retrieving profile." });
  }
};

// --- NEW: Forgot Password Logic ---
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      // Send a generic message to prevent email enumeration
      return res
        .status(200)
        .json({
          message:
            "If an account with that email exists, a password reset link has been sent.",
        });
    }

    // Generate a reset token (e.g., a random string)
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Hash the token and save it to the user in the database
    // We hash it to prevent timing attacks if someone gets access to the DB.
    // Though, the full token is sent via email, so the primary security is the token's randomness and expiry.
    const hashedResetToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Set token expiration (e.g., 1 hour from now)
    user.passwordResetToken = hashedResetToken;
    user.passwordResetExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Create the password reset URL for the frontend
    const resetURL = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    // Send the email
    const mailOptions = {
      from: process.env.EMAIL_USER, // Your sender email
      to: user.email,
      subject: "Password Reset Request",
      html: `
                <p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                <p>Please click on the following link, or paste this into your browser to complete the process:</p>
                <p><a href="${resetURL}">${resetURL}</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
            `,
    };

    await transporter.sendMail(mailOptions);

    res
      .status(200)
      .json({
        message:
          "If an account with that email exists, a password reset link has been sent.",
      });
  } catch (error) {
    console.error("Forgot password error:", error);
    // Important: Log error details but don't expose them to the client
    res.status(500).json({ message: "Error sending password reset email." });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token } = req.params; // Get token from URL parameter
    const { newPassword } = req.body; // Get new password from body

    if (!newPassword) {
      return res.status(400).json({ message: "New password is required." });
    }
    // Add password strength validation here

    // Hash the token from the URL to compare with the stored hashed token
    const hashedTokenFromURL = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedTokenFromURL,
      passwordResetExpires: { $gt: Date.now() }, // Check if token is not expired
    });

    if (!user) {
      return res
        .status(400)
        .json({ message: "Password reset token is invalid or has expired." });
    }

    // Hash the new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    // Clear the reset token fields
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password has been reset successfully." });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Error resetting password." });
  }
};

// --- NEW: Google Login Logic ---
exports.googleLogin = async (req, res) => {
  const { id_token } = req.body; // Google's ID token sent from the frontend

  if (!id_token) {
    return res.status(400).json({ message: "Google ID token is missing." });
  }

  try {
    // Verify the ID token with Google
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const googleId = payload["sub"]; // Google's unique user ID
    const email = payload["email"];
    const name = payload["name"]; // User's full name from Google profile

    // 1. Check if user already exists with this Google ID
    let user = await User.findOne({ googleId });

    if (user) {
      // User exists, log them in
      // Update email or username if it changed on Google? (optional)
      if (user.email !== email) user.email = email; // Update email if Google provides a different one
      if (!user.username && name)
        user.username = name.replace(/\s+/g, "").toLowerCase(); // Set username if not already set and name is available
      await user.save(); // Save any updates

      const token = generateToken(user._id, user.username || user.email);
      return res.status(200).json({
        message: "Login successful via Google!",
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          googleId: user.googleId,
        },
      });
    }

    // 2. If no user with Google ID, check if user exists with this email (might be a regular signup user linking Google)
    user = await User.findOne({ email });

    if (user) {
      // User exists with this email, link Google ID to existing account
      if (user.googleId) {
        // This scenario means an existing user tried to link Google, but their Google ID is different
        // Or another Google account tried to log in with an email already taken by a non-Google user
        return res
          .status(409)
          .json({ message: "An account with this email already exists." });
      }
      user.googleId = googleId;
      // Optionally, if the user previously signed up without a username, set it from Google
      if (!user.username && name) {
        user.username = name.replace(/\s+/g, "").toLowerCase();
      }
      await user.save();
      const token = generateToken(user._id, user.username || user.email);
      return res.status(200).json({
        message: "Google account linked and logged in!",
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          googleId: user.googleId,
        },
      });
    }

    // 3. New user, create a new account with Google ID
    const newGoogleUser = new User({
      googleId: googleId,
      email: email,
      username: name
        ? name.replace(/\s+/g, "").toLowerCase()
        : email.split("@")[0], // Create a simple username from name or email
      // Password will be null for Google-only sign-ups
    });
    await newGoogleUser.save();

    const token = generateToken(
      newGoogleUser._id,
      newGoogleUser.username || newGoogleUser.email
    );
    res.status(201).json({
      message: "User registered via Google!",
      token,
      user: {
        id: newGoogleUser._id,
        username: newGoogleUser.username,
        email: newGoogleUser.email,
        googleId: newGoogleUser.googleId,
      },
    });
  } catch (error) {
    console.error("Google login error:", error);
    res
      .status(500)
      .json({ message: "Google login failed. Invalid token or server error." });
  }
};
