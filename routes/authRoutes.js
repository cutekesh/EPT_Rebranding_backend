// routes/authRoutes.js
const express = require("express");
const router = express.Router(); 
const authController = require("../controllers/authController"); 
const authMiddleware = require("../middleware/authMiddleware"); 


router.post("/signup", authController.signup);
router.post("/login", authController.login);


router.get("/profile", authMiddleware.authenticateToken, (req, res) => {
  
  res.json({
    message: `Welcome to your profile, ${req.user.username}!`,
    userId: req.user.userId,
  });
});

// NEW: Forgot Password Routes
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password/:token', authController.resetPassword);

// NEW: Google OAuth Routes
router.post('/google-login', authController.googleLogin); // Frontend sends Google ID token here

// You can define other auth-related routes here (e.g., /forgot-password, /reset-password)

module.exports = router; // Export the router
