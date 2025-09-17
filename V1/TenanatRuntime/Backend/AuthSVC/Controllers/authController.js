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
        const registrationData = await authService.registerUser(
            email,
            password
        );

        // 3. Send the Response
        // The API contract for /auth/register specifies a 201 status code
        return res.status(201).json(registrationData);
    } catch (err) {
        // 4. Handle Errors from the Service Layer
        // Pass the error to the Express error handling middleware
        return next(err);
    }
}
async function loginUser(req, res, next) {}
async function enable2FA(req, res, next) {}
async function disable2FA(req, res, next) {}
async function setup2FA(req, res, next) {}
async function refresh2FABackupCodes(req, res, next) {}
async function getMe(req, res, next) {}

module.exports = {
    registerUser,
    loginUser,
    enable2FA,
    disable2FA,
    setup2FA,
    refresh2FABackupCodes,
    getMe,
};
