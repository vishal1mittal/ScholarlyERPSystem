const express = require("express");
const router = express.Router();
const authController = require("../Controllers/authController"); // Correct import path

router.post("/register", authController.registerUser);
router.post("/verify-mail", authController.verifyMail);
router.post("/resend-otp", authController.resendOtp);
// router.post("/login", authController);
// router.post("/me", authController);
router.post("/2fa/setup", authController.setup2FA);
router.post("/2fa/verify", authController.verify2FA);
router.post("/2fa/enable", authController.enable2FA);
router.post("/2fa/disable", authController.disable2FA);

module.exports = router;
