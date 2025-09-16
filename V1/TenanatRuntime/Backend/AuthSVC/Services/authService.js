const db = require("../../DB/db"); // Import our database module
const passwordUtil = require("../../Util/password");
const { createError } = require("../../Error/CustomErrorHandler");
const { getUTCDateTime } = require("../../Util/dateTime");

// This function will interact with your PostgreSQL database
async function registerUser(email, password, role) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // Check if a user with the same email already exists
        const userExistsQuery = "SELECT 1 FROM users WHERE email = $1;";
        const userExistsResult = await client.query(userExistsQuery, [email]);
        if (userExistsResult.rows.length > 0) {
            return next(createError("CONFLICT", "Email Already Exists", err));
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
            uuidv4(),
            process.env.TENANT_ID,
            email,
            passwordHash,
            role,
            true,
            false,
            getUTCDateTime(),
            getUTCDateTime(),
        ];
        const newUserResult = await client.query(newUserQuery, newUserValues);
        const newUserId = newUserResult.rows[0].id;

        // The documentation requires a user_id, access_token, and refresh_token in the response
        // You'll need to generate these here and return them
        const accessToken = "..."; // logic to create JWT
        const refreshToken = "..."; // logic to create JWT

        // Store a hashed version of the refresh token in the sessions table.
        const refreshTokenHash = await hashPassword(refreshToken);
        const newSessionQuery = `
            INSERT INTO sessions (id, user_id, tenant_id, refresh_token_hash, created_at, updated_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7);
        `;
        const newSessionValues = [
            uuidv4(),
            newUserId,
            "your-tenant-id-uuid", // Must match user's tenant_id
            refreshTokenHash,
            new Date(),
            new Date(),
            new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7-day lifetime
        ];
        await client.query(newSessionQuery, newSessionValues);

        await client.query("COMMIT");

        return {
            user_id: newUserId,
            access_token: accessToken,
            refresh_token: refreshToken,
        };
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}
async function loginUser() {}
async function enable2FA() {}
async function disable2FA() {}
async function setup2FA() {}
async function verify2FA() {}
async function getMe() {}

module.exports = {
    registerUser,
    loginUser,
    enable2FA,
    disable2FA,
    setup2FA,
    verify2FA,
    getMe,
};
