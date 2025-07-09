// app.js or server.js
const express = require("express");
const cors = require("cors");
require("dotenv").config(); // Load environment variables
const app = express();
const connectDB = require("./db/connection"); // Assuming you have a database connection setup
const authRoutes = require("./routes/authRoutes"); // Import your authentication routes

// Connect to Database
connectDB();

// Middleware
app.use(
  cors({
    origin: "https://ept-rebranding-6qd1.vercel.app/",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json()); // For parsing JSON request bodies

// Route Mounting
app.use("/api/auth", authRoutes); // All routes defined in authRoutes.js will be prefixed with /api/auth



// app.use('/api/users', userRoutes);


// Simple root route
app.get("/", (req, res) => {
  res.send("Backend API is running!");
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
