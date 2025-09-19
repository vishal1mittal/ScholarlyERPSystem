const { authenticate, authorize } = require("../Services/authService");
const { createError } = require("../../Error/CustomErrorHandler");
const authService = require("../Services/authService");
const feildValidator = require("../../Util/feildValidator");

async function registerUser(req, res, next) {
    // 1. Input Validation
    const { email, password } = req.body;

    if (!email || !password) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Email and Password are required",
                new Error("Email or Password Doesn't Exist")
            )
        );
    }

    if (!feildValidator.isValidEmail(email)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Email is Invalid",
                new Error(`Email is Invalid: ${email}`)
            )
        );
    }

    if (!feildValidator.isValidPassword(password)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Password is Invalid",
                new Error(`Invalid Password: ${password}`)
            )
        );
    }

    try {
        // 2. Call the Service Layer
        const registrationMessage = await authService.registerUser(
            email,
            password
        );

        // 3. Send the Response
        // The API contract for /auth/register specifies a 201 status code
        return res.status(201).json(registrationMessage);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}

async function verifyMail(req, res, next) {
    // 1. Input Validation
    const { email, otp } = req.body;

    if (!email || !otp) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Email and OTP are required",
                new Error("Email or OTP Doesn't Exist")
            )
        );
    }

    if (!feildValidator.isValidEmail(email)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Email is Invalid",
                new Error(`Email is Invalid: ${email}`)
            )
        );
    }

    if (!feildValidator.isValidOTP(otp)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "OTP is Invalid",
                new Error(`Invalid OTP: ${otp}`)
            )
        );
    }

    try {
        // 2. Call the Service Layer
        const registrationData = await authService.verifyMail(email, otp);

        // 3. Send the Response
        // The API contract for /auth/register specifies a 201 status code
        return res.status(201).json(registrationData);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}

async function resendOtp(req, res, next) {
    // 1. Input Validation
    const { email } = req.body;

    if (!email) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Email is required",
                new Error("Email Doesn't Exist")
            )
        );
    }

    if (!feildValidator.isValidEmail(email)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Email is Invalid",
                new Error(`Email is Invalid: ${email}`)
            )
        );
    }

    try {
        // 2. Call the Service Layer
        const registrationMessage = await authService.resendOtp(email);

        // 3. Send the Response
        // The API contract for /auth/register specifies a 201 status code
        return res.status(201).json(registrationMessage);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}

async function loginUser(req, res, next) {}

async function refreshAccessToken(refreshToken, opaqueToken) {}

async function setup2FA(req, res, next) {
    const userId = req.user.id;
    const { password } = req.body;

    // 1. Input Validation
    if (!userId) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id is required",
                new Error("User Id Doesn't Exist")
            )
        );
    }

    if (!feildValidator.isValidUUID(userId)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id is Invalid",
                new Error(`User Id is Invalid: ${userId}`)
            )
        );
    }

    if (!feildValidator.isValidPassword(password)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Password is Invalid",
                new Error(`Invalid Password: ${password}`)
            )
        );
    }

    try {
        // 2. Call the Service Layer
        const twoFAMessage = await authService.setup2FA(userId, password);

        // 3. Send the Response
        return res.status(201).json(twoFAMessage);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}

async function verifyTOTP2FA(req, res, next) {
    const userId = req.user.id;
    const { totp } = req.body;

    // 1. Input Validation
    if (!userId || !totp) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id and TOTP are required",
                new Error("User Id or TOTP Doesn't Exist")
            )
        );
    }

    if (!feildValidator.isValidUUID(userId)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id is Invalid",
                new Error(`User Id is Invalid: ${userId}`)
            )
        );
    }

    if (!feildValidator.isValidOTP(totp)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "TOTP is Invalid",
                new Error(`TOTP Password: ${totp}`)
            )
        );
    }

    try {
        // 2. Call the Service Layer
        const twoFAMessage = await authService.verifyTOTP2FA(userId, totp);

        // 3. Send the Response
        return res.status(201).json(twoFAMessage);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}

async function verifyBackupCode2FA(req, res, next) {
    const userId = req.user.id;
    const { backupCode } = req.body;

    // 1. Input Validation
    if (!userId || !backupCode) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id and Backup Code are required",
                new Error("User Id or Backup Code Doesn't Exist")
            )
        );
    }

    if (!feildValidator.isValidUUID(userId)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id is Invalid",
                new Error(`User Id is Invalid: ${userId}`)
            )
        );
    }

    if (!feildValidator.isValidBackupCode(backupCode)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Backup Code is Invalid",
                new Error(`Invalid Backup Code: ${backupCode}`)
            )
        );
    }

    try {
        // 2. Call the Service Layer
        const twoFAMessage = await authService.verifyBackupCode2FA(
            userId,
            backupCode
        );

        // 3. Send the Response
        return res.status(201).json(twoFAMessage);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}

async function enable2FA(req, res, next) {
    const userId = req.user.id;
    const { totp } = req.body;

    // 1. Input Validation
    if (!userId || !totp) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id and TOTP are required",
                new Error("User Id or TOTP Doesn't Exist")
            )
        );
    }

    if (!feildValidator.isValidUUID(userId)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id is Invalid",
                new Error(`User Id is Invalid: ${userId}`)
            )
        );
    }

    if (!feildValidator.isValidOTP(totp)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "TOTP is Invalid",
                new Error(`TOTP Password: ${totp}`)
            )
        );
    }

    try {
        // 2. Call the Service Layer
        const twoFAMessage = await authService.enable2FA(userId, totp);

        // 3. Send the Response
        return res.status(201).json(twoFAMessage);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}

async function disable2FA(req, res, next) {
    const userId = req.user.id;
    const { totp } = req.body;

    // 1. Input Validation
    if (!userId || !totp) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id and TOTP are required",
                new Error("User Id or TOTP Doesn't Exist")
            )
        );
    }

    if (!feildValidator.isValidUUID(userId)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id is Invalid",
                new Error(`User Id is Invalid: ${userId}`)
            )
        );
    }

    if (!feildValidator.isValidOTP(totp)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "TOTP is Invalid",
                new Error(`TOTP Password: ${totp}`)
            )
        );
    }

    try {
        // 2. Call the Service Layer
        const twoFAMessage = await authService.disable2FA(userId, totp);

        // 3. Send the Response
        return res.status(201).json(twoFAMessage);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}

async function refresh2FABackupCodes(req, res, next) {
    const userId = req.user.id;
    const { password, totp, backupCode } = req.body;

    // 1. Input Validation
    if (!userId || !password) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id and Password are required",
                new Error("User Id or Password Doesn't Exist")
            )
        );
    }

    // Check for either TOTP or Backup Code, not both
    if ((totp && backupCode) || (!totp && !backupCode)) {
        return next(
            createError(
                "BAD_REQUEST",
                "Must provide either TOTP or a Backup Code, but not both",
                new Error("Invalid 2FA proof provided")
            )
        );
    }

    if (!feildValidator.isValidUUID(userId)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "User Id is Invalid",
                new Error(`User Id is Invalid: ${userId}`)
            )
        );
    }

    if (!feildValidator.isValidPassword(password)) {
        // Use the centralized error handling module
        return next(
            createError(
                "BAD_REQUEST",
                "Password is Invalid",
                new Error(`Invalid Password: ${password}`)
            )
        );
    }

    // Check for a valid TOTP or a valid backup code.
    if (totp) {
        if (!feildValidator.isValidOTP(totp)) {
            return next(
                createError(
                    "BAD_REQUEST",
                    "TOTP is Invalid",
                    new Error(`TOTP Password: ${totp}`)
                )
            );
        }
    } else if (backupCode) {
        if (!feildValidator.isValidBackupCode(backupCode)) {
            return next(
                createError(
                    "BAD_REQUEST",
                    "Backup Code is Invalid",
                    new Error(`Backup Code: ${backupCode}`)
                )
            );
        }
    }

    try {
        // 2. Call the Service Layer
        const twoFAMessage = await authService.refresh2FABackupCodes(
            userId,
            password,
            totp,
            backupCode
        );

        // 3. Send the Response
        return res.status(201).json(twoFAMessage);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}
async function getMe(req, res, next) {}

module.exports = {
    registerUser,
    verifyMail,
    resendOtp,
    loginUser,
    enable2FA,
    disable2FA,
    setup2FA,
    verifyTOTP2FA,
    verifyBackupCode2FA,
    refresh2FABackupCodes,
    getMe,
};
