const express = require("express");
const router = express.Router();
const authController = require("../Controllers/authController"); // Correct import path
const { authenticate, authorize } = require("../authMiddleware");

/**
 * @openapi
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     description: Registers a new user by creating a temporary record and sending a verification OTP via email.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: "vishalmittalrohini@gmail.com"
 *               password:
 *                 type: string
 *                 example: "testingA@1"
 *     responses:
 *       200:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *       400:
 *         description: Invalid input
 *       500:
 *         description: Server error
 */

router.post("/register", authController.registerUser);

/**
 * @openapi
 * /auth/resend-otp:
 *   post:
 *     summary: Resend verification OTP
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 example: "vishalmittalrohini@gmail.com"
 *     responses:
 *       200:
 *         description: OTP resent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message: { type: string }
 *       400:
 *         description: Invalid email
 */

router.post("/resend-otp", authController.resendOtp);

/**
 * @openapi
 * /auth/verify-mail:
 *   post:
 *     summary: Verify a user's email
 *     description: Activates a user's account using an OTP sent via email.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - otp
 *             properties:
 *               email:
 *                 type: string
 *                 example: "vishalmittalrohini@gmail.com"
 *               otp:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Email verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userId: { type: string }
 *                 accessToken: { type: string }
 *                 refreshToken: { type: string }
 *                 opaqueToken: { type: string }
 *                 sessionId: { type: string }
 *       400:
 *         description: Invalid OTP or email
 *       500:
 *         description: Server error
 */

router.post("/verify-mail", authController.verifyMail);

/**
 * @openapi
 * /auth/logout:
 *   post:
 *     summary: Logs the user out by revoking the active session.
 *     description: Requires a valid Bearer JWT in the header and a sessionId in the request body.
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - sessionId
 *             properties:
 *               sessionId:
 *                 type: string
 *                 format: uuid
 *                 example: ""
 *     responses:
 *       201:
 *         description: Logout successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Logged out"
 *       400:
 *         description: Bad Request — missing or invalid sessionId
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Session Id is required"
 *       401:
 *         description: Unauthorized — invalid or missing JWT
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unauthorized"
 *       500:
 *         description: Internal Server Error — unexpected failure during logout
 */

router.post("/logout", authenticate, authController.logoutUser);

/**
 * @openapi
 * /auth/login:
 *   post:
 *     summary: Log in user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email: { type: string, example: "vishalmittalrohini@gmail.com" }
 *               password: { type: string, example: "testingA@1" }
 *               totp: { type: string }
 *               backupCode: { type: string }
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userId: { type: string }
 *                 accessToken: { type: string }
 *                 refreshToken: { type: string }
 *                 opaqueToken: { type: string }
 *                 sessionId: { type: string }
 *       401:
 *         description: Invalid credentials or 2FA failure
 */

router.post("/login", authController.loginUser);

/**
 * @openapi
 * /auth/refresh-access-token:
 *   post:
 *     summary: Refresh access token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *               - opaqueToken
 *             properties:
 *               refreshToken: { type: string }
 *               opaqueToken: { type: string }
 *     responses:
 *       200:
 *         description: New access token generated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken: { type: string }
 *       400:
 *         description: Invalid tokens
 */

router.post("/refresh-access-token", authController.refreshAccessToken);

/**
 * @openapi
 * /auth/2fa/setup:
 *   post:
 *     summary: Setup 2FA
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [password]
 *             properties:
 *               password: { type: string }
 *     responses:
 *       200:
 *         description: 2FA setup initiated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 qr_code_url: { type: string }
 *                 secret: { type: string }
 */

router.post("/2fa/setup", authenticate, authController.setup2FA);

/**
 * @openapi
 * /auth/2fa/verify-totp:
 *   post:
 *     summary: Verify TOTP
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [totp]
 *             properties:
 *               totp: { type: string }
 *     responses:
 *       200:
 *         description: TOTP verified
 *       400:
 *         description: Invalid TOTP
 */

router.post("/2fa/verify-totp", authenticate, authController.verifyTOTP2FA);

/**
 * @openapi
 * /auth/2fa/verify-backup-code:
 *   post:
 *     summary: Verify backup code
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [backupCode]
 *             properties:
 *               backupCode: { type: string }
 *     responses:
 *       200:
 *         description: Backup code verified
 *       400:
 *         description: Invalid backup code
 */

router.post(
    "/2fa/verify-backup-code",
    authenticate,
    authController.verifyBackupCode2FA
);

/**
 * @openapi
 * /auth/2fa/enable:
 *   post:
 *     summary: Enable 2FA
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [totp]
 *             properties:
 *               totp: { type: string }
 *     responses:
 *       200:
 *         description: 2FA enabled
 *       400:
 *         description: Invalid TOTP
 */

router.post("/2fa/enable", authenticate, authController.enable2FA);

/**
 * @openapi
 * /auth/2fa/disable:
 *   post:
 *     summary: Disable 2FA
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [totp]
 *             properties:
 *               totp: { type: string }
 *     responses:
 *       200:
 *         description: 2FA disabled
 *       400:
 *         description: Invalid TOTP
 */

router.post("/2fa/disable", authenticate, authController.disable2FA);

/**
 * @openapi
 * /auth/2fa/refresh-backup-codes:
 *   post:
 *     summary: Refresh backup codes
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [password]
 *             properties:
 *               password: { type: string }
 *               totp: { type: string }
 *               backupCode: { type: string }
 *     responses:
 *       200:
 *         description: Backup codes refreshed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message: { type: string }
 *                 backupCodes: { type: string }
 *       400:
 *         description: Invalid credentials
 */

router.post(
    "/2fa/refresh-backup-codes",
    authenticate,
    authController.refresh2FABackupCodes
);

/**
 * @openapi
 * /auth/profile:
 *   get:
 *     summary: Get user profile
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Profile fetched
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user_id: { type: string }
 *                 email: { type: string }
 *                 role: { type: string }
 *                 mfa_enabled: { type: boolean }
 *                 profile_data: { type: object }
 *       401:
 *         description: Unauthorized
 */

router.get(
    "/profile/:targetUserId",
    authenticate,
    authorize("user_profile_viewing_allowed"),
    authController.getProfile
);

/**
 * @openapi
 * /auth/update-role:
 *   post:
 *     summary: Update user role
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - targetUserId
 *               - newRole
 *             properties:
 *               targetUserId: { type: string }
 *               newRole: { type: string }
 *     responses:
 *       200:
 *         description: Role updated
 *       403:
 *         description: Forbidden, insufficient permissions
 */

router.post(
    "/update-role",
    authenticate,
    authorize("role_updation_allowed"),
    authController.updateUserRole
);

/**
 * @openapi
 * /auth/delete-user:
 *   post:
 *     summary: Delete a user account
 *     description: >
 *       Deletes a user account.
 *       - If `targetUserId` is not provided, the authenticated user deletes **their own account** (self-deletion).
 *       - If `targetUserId` is provided and differs from the authenticated user, the caller must have the
 *         `delete_user_with_role` permission in addition to authentication.
 *       - In all cases, the request must include the requester's password and a valid 2FA credential (TOTP or backup code)
 *         for confirmation, as this is a destructive action.
 *     security:
 *       - bearerAuth: []
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               targetUserId:
 *                 type: string
 *                 format: uuid
 *                 description: >
 *                   The ID of the user to delete.
 *                   If omitted, the authenticated user's own account is deleted.
 *               password:
 *                 type: string
 *                 description: Password of the requesting user (for identity confirmation).
 *               totp:
 *                 type: string
 *                 description: Current TOTP code (if 2FA enabled).
 *               backupCode:
 *                 type: string
 *                 description: Backup code (used instead of TOTP if needed).
 *             example:
 *               targetUserId: "f3a5e4b0-1234-4567-89ab-ef9876543210"
 *               password: "testingA@1"
 *               totp: "123456"
 *     responses:
 *       200:
 *         description: User deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "User account deleted successfully."
 *       400:
 *         description: Bad Request — invalid targetUserId or missing required fields
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Target User ID is invalid."
 *       401:
 *         description: Unauthorized — invalid or missing JWT
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Unauthorized"
 *       403:
 *         description: Forbidden — attempting to delete another user without proper permissions
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "You do not have permission to delete other user accounts."
 *       500:
 *         description: Internal Server Error — unexpected failure during deletion
 */

router.post(
    "/delete-user",
    authenticate,
    authorize("user_deletion_allowed"),
    authController.deleteUser
);

module.exports = router;
