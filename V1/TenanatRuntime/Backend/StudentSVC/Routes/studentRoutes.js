const express = require("express");
const router = express.Router();
const studentController = require("../Controllers/studentController"); // Correct import path
const { authenticate, authorize } = require("../../AuthSVC/authMiddleware");

router.get(
    "/get-students",
    authenticate, // 1. Verify JWT
    authorize("list_all_students"), // 2. Check general permission
    studentController.getStudents // 3. Execute controller logic
);

module.exports = router;
