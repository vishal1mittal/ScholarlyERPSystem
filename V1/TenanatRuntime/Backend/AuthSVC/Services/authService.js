const db = require("../../DB/db"); // Import our database module
const passwordUtil = require("../../Util/password");
const tokensUtil = require("../../Util/tokens");
const sessionsUtil = require("../../Util/session");
const { getUTCDateTime } = require("../../Util/dateTime");
const { createError } = require("../../Error/CustomErrorHandler");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const otpEmailTemplate = require("../../Util/otpEmailTemplate"); // Assuming this utility exists

// This function will interact with your PostgreSQL database
async function registerUser(email, password) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // Check if a user with the same email already exists
        const userExistsQuery = "SELECT 1 FROM users WHERE email = $1;";
        const userExistsResult = await client.query(userExistsQuery, [email]);
        if (userExistsResult.rows.length > 0) {
            throw createError("CONFLICT", "Email Already Exists");
        }

        // Hash the password using Argon2, as specified in the docs.
        const passwordHash = await passwordUtil.hashPassword(password);

        // Insert the new user into the users table
        const newUserQuery = `
            INSERT INTO users (id, tenant_id, email, password_hash, role, is_active, mfa_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id;
        `;
        const newUserValues = [
            crypto.randomUUID(),
            process.env.TENANT_ID,
            email,
            passwordHash,
            process.env.LEAST_PRIVILEGE_ROLE,
            true,
            false,
            getUTCDateTime(),
            getUTCDateTime(),
        ];
        const newUserResult = await client.query(newUserQuery, newUserValues);
        const newUser = newUserResult.rows[0];
        const newUserId = newUser.id;

        // The documentation requires a user_id, access_token, and refresh_token in the response
        // You'll need to generate these here and return them
        let session, refreshToken, opaqueToken;

        try {
            const sessionData = await sessionsUtil.createSession(
                client,
                newUserId
            );
            // Assign values to the variables declared outside
            session = sessionData.session;
            refreshToken = sessionData.refreshToken;
            opaqueToken = sessionData.opaqueToken;
        } catch (err) {
            // Return an error response if session creation fails
            throw createError(
                "INTERNAL_SERVER_ERROR",
                "Error Creating Session",
                err
            );
        }

        const accessToken = tokensUtil.generateAccessToken(newUser); // logic to create JWT

        await client.query("COMMIT");

        return {
            user_id: newUserId,
            access_token: accessToken,
            refresh_token: refreshToken,
            opaque_token: opaqueToken,
            session_id: session.id,
        };
    } catch (err) {
        await client.query("ROLLBACK");
        throw err;
    } finally {
        client.release();
    }
}
async function loginUser() {}
async function enable2FA() {}
async function disable2FA() {}
async function setup2FA() {}
async function refresh2FABackupCodes() {}
async function getMe() {}

module.exports = {
    registerUser,
    loginUser,
    enable2FA,
    disable2FA,
    setup2FA,
    refresh2FABackupCodes,
    getMe,
};
