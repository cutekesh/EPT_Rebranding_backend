// Import the mongoose library for interacting with MongoDB.
const mongoose = require("mongoose");

// Define an asynchronous function 'connectDB' to establish a connection to the MongoDB database.
const connectDB = async () => {
  try {
    // Attempt to connect to MongoDB using the connection string stored in the environment variable MONGO_URI.
    await mongoose.connect(process.env.MONGO_URL);
    // Log a success message to the console if the connection is successful.
    console.log("Connected to MongoDB successfully");
  } catch (err) {
    // If an error occurs during the connection, log the error message to the console.
    console.error("MongoDB connection error:", err.message);
    // Exit the process with a failure code (1) to indicate the connection failure.
    process.exit(1);
  }
};

// Export the connectDB function so that it can be used elsewhere in the application.
module.exports = connectDB;
