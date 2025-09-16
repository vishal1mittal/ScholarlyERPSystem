const express = require("express");
const router = express.Router();
const authController = require("../Controllers/authController"); // Correct import path

router.post("/register", authController.registerUser);
// router.post("/login", tenantController.createTenantController);
// router.post("/me", tenantController.createTenantController);
// router.post("/2fa/setup", tenantController.createTenantController);
// router.post("/2fa/verify", tenantController.createTenantController);
// router.post("/2fa/enable", tenantController.createTenantController);
// router.post("/2fa/disable", tenantController.createTenantController);

module.exports = router;
