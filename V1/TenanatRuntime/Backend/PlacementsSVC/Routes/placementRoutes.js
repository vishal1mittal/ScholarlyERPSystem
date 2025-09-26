const express = require("express");
const router = express.Router();
const authController = require("../Controllers/authController"); // Correct import path
const { authenticate, authorize } = require("../authMiddleware");

module.exports = router;
