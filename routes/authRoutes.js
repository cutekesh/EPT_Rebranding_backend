// routes/authRoutes.js
const express = require("express");
const router = express.Router(); // Create an Express Router instance
const authController = require("../controllers/authController"); // Import your controller functions
const authMiddleware = require("../middleware/authMiddleware"); // Import your middleware

// Define authentication routes
router.post("/signup", authController.signup);
router.post("/login", authController.login);

// Example of a protected route
router.get("/profile", authMiddleware.authenticateToken, (req, res) => {
  // This route is only accessible if the token is valid
  res.json({
    message: `Welcome to your profile, ${req.user.username}!`,
    userId: req.user.userId,
  });
});

// You can define other auth-related routes here (e.g., /forgot-password, /reset-password)

module.exports = router; // Export the router
