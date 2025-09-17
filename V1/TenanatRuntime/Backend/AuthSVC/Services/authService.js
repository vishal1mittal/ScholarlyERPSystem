const db = require("../../DB/db"); // Import our database module
const passwordUtil = require("../../Util/password");
const tokensUtil = require("../../Util/tokens");
const sessionsUtil = require("../../Util/session");
const { getUTCDateTime } = require("../../Util/dateTime");
const { createError } = require("../../Error/CustomErrorHandler");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { otpEmailTemplate } = require("../../Util/emailTemplate"); // Assuming this utility exists
const twofaUtil = require("../../Util/twoFA");

// This function will interact with your PostgreSQL database

async function registerUser(email, password) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // Check if a user with the same email already exists in either table
        const userExistsQuery =
            "SELECT 1 FROM users WHERE email = $1 UNION ALL SELECT 1 FROM temp_users WHERE email = $1;";
        const userExistsResult = await client.query(userExistsQuery, [email]);
        if (userExistsResult.rows.length > 0) {
            throw createError("CONFLICT", "Email Already Exists");
        }

        // Generate and hash OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        const otpHash = await passwordUtil.hashPassword(otp);

        // Insert into the temporary users table
        const tempUserQuery = `
            INSERT INTO temp_users (id, tenant_id, email, password_hash, otp_hash, otp_expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
            RETURNING *;
        `;
        const tempUserValues = [
            crypto.randomUUID(),
            process.env.TENANT_ID,
            email,
            await passwordUtil.hashPassword(password),
            otpHash,
            getUTCDateTime(Date.now() + 5 * 60 * 1000), // 5-minute expiration
            getUTCDateTime(),
        ];
        await client.query(tempUserQuery, tempUserValues);

        // Send OTP email
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_ID,
                pass: process.env.EMAIL_PASS,
            },
        });
        await transporter.sendMail({
            from: `"Scholarly ERP" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "Verify your email",
            html: otpEmailTemplate({ name: email.split("@")[0], otp: otp }),
        });

        await client.query("COMMIT");
        return { message: "User registered, check your email for OTP" };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during registration",
            error
        );
    } finally {
        client.release();
    }
}

// AuthSVC/Services/authService.js

async function verifyMail(email, otp) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // 1. Find the temporary user
        const tempUserQuery = `SELECT * FROM temp_users WHERE email = $1 AND otp_expires_at > $2;`;
        const tempUserResult = await client.query(tempUserQuery, [
            email,
            getUTCDateTime(),
        ]);
        const tempUser = tempUserResult.rows[0];

        if (!tempUser) {
            throw createError("BAD_REQUEST", "Invalid or expired OTP");
        }

        // 2. Verify the OTP
        const isOtpValid = await passwordUtil.verifyPassword(
            tempUser.otp_hash,
            otp
        );
        if (!isOtpValid) {
            throw createError("BAD_REQUEST", "Invalid OTP");
        }

        // 3. Create the permanent user record
        const newUserQuery = `
            INSERT INTO users (id, tenant_id, email, password_hash, role, is_active, mfa_enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, tenant_id, email, role;
        `;
        const newUserValues = [
            crypto.randomUUID(),
            process.env.TENANT_ID,
            tempUser.email,
            tempUser.password_hash,
            process.env.LEAST_PRIVILEGE_ROLE,
            true,
            false,
            getUTCDateTime(),
            getUTCDateTime(),
        ];
        const newUserResult = await client.query(newUserQuery, newUserValues);
        const newUser = newUserResult.rows[0];

        // 4. Create the session and tokens
        const { session, refreshToken, opaqueToken } =
            await sessionsUtil.createSession(
                client,
                newUser.id,
                newUser.tenant_id
            );
        const accessToken = tokensUtil.generateAccessToken(newUser);

        // 5. Delete the temporary user record
        const deleteTempUserQuery = `DELETE FROM temp_users WHERE email = $1;`;
        await client.query(deleteTempUserQuery, [email]);

        await client.query("COMMIT");

        return {
            user_id: newUser.id,
            access_token: accessToken,
            refresh_token: refreshToken,
            opaque_token: opaqueToken,
            session_id: session.id,
        };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during verification",
            error
        );
    } finally {
        client.release();
    }
}

// AuthSVC/Services/authService.js

async function resendOtp(email) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // 1. Check if the user is already verified
        const userExistsQuery = "SELECT * FROM users WHERE email = $1;";
        const userExistsResult = await client.query(userExistsQuery, [email]);
        if (userExistsResult.rows.length > 0) {
            throw createError("BAD_REQUEST", "Email is already verified");
        }

        // 2. Find the temporary user
        const tempUserQuery = "SELECT * FROM temp_users WHERE email = $1;";
        const tempUserResult = await client.query(tempUserQuery, [email]);
        const tempUser = tempUserResult.rows[0];
        if (!tempUser) {
            throw createError("NOT_FOUND", "User not found");
        }

        // 3. Generate a new OTP and update the temporary record
        const newOtp = crypto.randomInt(100000, 999999).toString();
        const newOtpHash = await passwordUtil.hashPassword(newOtp);
        const updateQuery = `
            UPDATE temp_users
            SET otp_hash = $1, otp_expires_at = $2, updated_at = $3
            WHERE email = $4;
        `;
        const updateValues = [
            newOtpHash,
            getUTCDateTime(Date.now() + 5 * 60 * 1000), // New 5-minute expiration
            getUTCDateTime(),
            email,
        ];
        await client.query(updateQuery, updateValues);

        // 4. Send the new OTP via email
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_ID,
                pass: process.env.EMAIL_PASS,
            },
        });
        await transporter.sendMail({
            from: `"Scholarly ERP" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: "New OTP for email verification",
            html: otpEmailTemplate({ name: email.split("@")[0], otp: newOtp }),
        });

        await client.query("COMMIT");
        return { message: "New OTP sent" };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during OTP resend",
            error
        );
    } finally {
        client.release();
    }
}

async function loginUser() {}
async function enable2FA(userId, otp) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // Fetch the user's current 2FA secret
        const userQuery = "SELECT mfa_secret FROM users WHERE id = $1";
        const userResult = await client.query(userQuery, [userId]);
        const user = userResult.rows[0];

        if (!user || !user.mfa_secret) {
            throw createError("BAD_REQUEST", "2FA setup not initiated");
        }

        // Verify the provided OTP against the secret
        const isValid = twofaUtil.verifyTOTP(user.mfa_secret, otp);
        if (!isValid) {
            throw createError("UNAUTHORIZED", "Invalid credentials");
        }

        // Update the user record to enable 2FA
        const updateQuery = `
            UPDATE users SET mfa_enabled = TRUE, updated_at = $1 WHERE id = $2
        `;
        await client.query(updateQuery, [getUTCDateTime(), userId]);

        await client.query("COMMIT");
        return { message: "2FA enabled successfully." };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during Enabling 2FA",
            error
        );
    } finally {
        client.release();
    }
}
async function disable2FA(userId, otp) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // Fetch the user's current 2FA status and secret
        const userQuery =
            "SELECT mfa_enabled, mfa_secret FROM users WHERE id = $1";
        const userResult = await client.query(userQuery, [userId]);
        const user = userResult.rows[0];

        if (!user || !user.mfa_enabled) {
            throw createError(
                "BAD_REQUEST",
                "2FA is not enabled for this user"
            );
        }

        // Verify the provided OTP
        const isValid = twofaUtil.verifyTOTP(user.mfa_secret, otp);
        if (!isValid) {
            throw createError("UNAUTHORIZED", "Invalid OTP");
        }

        // Update the user record to disable 2FA
        const updateQuery = `
            UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, updated_at = $1 WHERE id = $2
        `;
        await client.query(updateQuery, [getUTCDateTime(), userId]);

        await client.query("COMMIT");
        return { message: "2FA disabled successfully." };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during disabling 2FA",
            error
        );
    } finally {
        client.release();
    }
}
async function setup2FA(userId, password) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN"); // Start a transaction

        // 1. Fetch user to get their email and check if 2FA is already enabled.
        const userQuery =
            "SELECT email, password_hash, mfa_enabled FROM users WHERE id = $1";
        const userResult = await client.query(userQuery, [userId]);
        const user = userResult.rows[0];

        if (!user) {
            throw createError("NOT_FOUND", "User not found");
        }
        if (
            !(await passwordUtil.verifyPassword(user.password_hash, password))
        ) {
            throw createError("UNAUTHORIZED", "Invalid Password");
        }
        if (user.mfa_enabled) {
            throw createError(
                "BAD_REQUEST",
                "2FA is already enabled for this user"
            );
        }

        // 2. Generate a new TOTP secret.
        const { base32, otpauthUrl } = await twofaUtil.generateTOTPSecret(
            user.email
        );

        // 3. Update the user's record with the new secret.
        const updateQuery =
            "UPDATE users SET mfa_secret = $1 WHERE id = $2 RETURNING mfa_secret;";
        await client.query(updateQuery, [base32, userId]);

        await client.query("COMMIT"); // End the transaction

        return {
            qr_code_url: otpauthUrl,
            secret: base32,
        };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during 2FA setup",
            error
        );
    } finally {
        client.release();
    }
}

async function verify2FA(userId, otp) {
    const client = await db.pool.connect();
    try {
        // No transaction needed, as this is a read-only operation.

        // 1. Fetch the user's mfa_secret
        const userQuery = "SELECT mfa_secret FROM users WHERE id = $1";
        const userResult = await client.query(userQuery, [userId]);
        const user = userResult.rows[0];

        if (!user || !user.mfa_secret) {
            throw createError(
                "BAD_REQUEST",
                "2FA not configured for this user"
            );
        }

        // 2. Verify the TOTP code.
        const isValid = twofaUtil.verifyTOTP(user.mfa_secret, otp);

        // Don't commit or rollback here as there's no transaction.

        return { success: isValid };
    } catch (error) {
        // No rollback needed for a read-only function
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during Verifying 2FA",
            error
        );
    } finally {
        client.release();
    }
}
async function refresh2FABackupCodes() {}
async function getMe() {}

module.exports = {
    registerUser,
    verifyMail,
    resendOtp,
    loginUser,
    enable2FA,
    disable2FA,
    setup2FA,
    verify2FA,
    refresh2FABackupCodes,
    getMe,
};
