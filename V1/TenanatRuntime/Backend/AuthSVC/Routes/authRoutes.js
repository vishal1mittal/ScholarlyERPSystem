const express = require("express");
const router = express.Router();
const authController = require("../Controllers/authController"); // Correct import path
const { authenticate, authorize } = require("../authMiddleware");

router.post("/register", authController.registerUser);
router.post("/verify-mail", authController.verifyMail);
router.post("/resend-otp", authController.resendOtp);
router.post("/login", authController.loginUser);
router.post("/logout", authenticate, authController.logoutUser);
router.post("/refresh-access-token", authController.refreshAccessToken);
router.post("/update-role", authenticate, authController.updateUserRole);
router.post("/profile", authenticate, authController.getProfile);
router.post("/2fa/setup", authenticate, authController.setup2FA);
router.post("/2fa/verify-totp", authenticate, authController.verifyTOTP2FA);
router.post(
    "/2fa/verify-backup-code",
    authenticate,
    authController.verifyBackupCode2FA
);
router.post("/2fa/enable", authenticate, authController.enable2FA);
router.post("/2fa/disable", authenticate, authController.disable2FA);
router.post(
    "/2fa/refresh-backup-codes",
    authenticate,
    authController.refresh2FABackupCodes
);

module.exports = router;
