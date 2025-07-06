// app.js or server.js
const express = require("express");
const cors = require("cors");
require("dotenv").config(); // Load environment variables
const app = express();
const connectDB = require("./db/connection"); // Assuming you have a database connection setup
const authRoutes = require("./routes/authRoutes"); // Import your authentication routes
// const protectedRoutes = require('./routes/protectedRoutes'); // If you have other route files

// Connect to Database (example)
connectDB();

// Middleware
app.use(
  cors({
    origin: "https://ept-rebranding-6qd1.vercel.app/", // Replace with your frontend's actual URL
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json()); // For parsing JSON request bodies

// Route Mounting
app.use("/api/auth", authRoutes); // All routes defined in authRoutes.js will be prefixed with /api/auth
// Example: /api/auth/signup, /api/auth/login, /api/auth/profile

// If you had other route files:
// app.use('/api/users', userRoutes);
// app.use('/api/products', productRoutes);

// Simple root route
app.get("/", (req, res) => {
  res.send("Backend API is running!");
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
