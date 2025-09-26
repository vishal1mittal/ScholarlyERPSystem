const express = require("express");
const router = express.Router();
const authController = require("../Controllers/placementController"); // Correct import path
const { authenticate, authorize } = require("../../AuthSVC/authMiddleware");

module.exports = router;
