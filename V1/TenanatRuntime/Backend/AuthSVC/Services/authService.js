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
const rolesUtil = require("../../Util/roles");

// This function will interact with your PostgreSQL database

async function registerUser(email, password) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        // Check if a user with the same email already exists in either table
        const userExistsQuery =
            "SELECT 1 FROM users WHERE email = $1 AND tenant_id = $2 UNION ALL SELECT 1 FROM temp_users WHERE email = $1 AND tenant_id = $2;";
        const userExistsResult = await client.query(userExistsQuery, [
            email,
            tenantId,
        ]);
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
            tenantId,
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

async function verifyMail(email, otp) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        // 1. Find the temporary user
        const tempUserQuery = `SELECT * FROM temp_users WHERE email = $1 AND otp_expires_at > $2 AND tenant_id = $3;`;
        const tempUserResult = await client.query(tempUserQuery, [
            email,
            getUTCDateTime(),
            tenantId,
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
            RETURNING id, tenant_id, email, role;
        `;
        const newUserValues = [
            crypto.randomUUID(),
            tenantId,
            tempUser.email,
            tempUser.password_hash,
            process.env.LEAST_PRIVILEGE_ROLE,
            true,
            false,
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
        const deleteTempUserQuery = `DELETE FROM temp_users WHERE email = $1 AND tenant_id = $2;`;
        await client.query(deleteTempUserQuery, [email, tenantId]);

        await client.query("COMMIT");

        return {
            userId: newUser.id,
            accessToken: accessToken,
            refreshToken: refreshToken,
            opaqueToken: opaqueToken,
            sessionId: session.id,
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

async function resendOtp(email) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        // 1. Check if the user is already verified
        const userExistsQuery =
            "SELECT * FROM users WHERE email = $1 AND tenant_id = $2;";
        const userExistsResult = await client.query(userExistsQuery, [
            email,
            tenantId,
        ]);
        if (userExistsResult.rows.length > 0) {
            throw createError("BAD_REQUEST", "Email is already verified");
        }

        // 2. Find the temporary user
        const tempUserQuery =
            "SELECT * FROM temp_users WHERE email = $1 AND tenant_id = $2;";
        const tempUserResult = await client.query(tempUserQuery, [
            email,
            tenantId,
        ]);
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
            WHERE email = $4 AND tenant_id = $5;
        `;
        const updateValues = [
            newOtpHash,
            getUTCDateTime(Date.now() + 5 * 60 * 1000), // New 5-minute expiration
            getUTCDateTime(),
            email,
            tenantId,
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

async function loginUser(email, password, totp, backupCode) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        // 1. Find the user by email
        const userQuery =
            "SELECT id, tenant_id, email, password_hash, role, mfa_enabled, is_active FROM users WHERE email = $1 AND tenant_id = $2;";
        const userResult = await client.query(userQuery, [email, tenantId]);
        const user = userResult.rows[0];

        if (!user || !user.is_active) {
            throw createError("UNAUTHORIZED", "Invalid credentials");
        }

        // 2. Verify password
        const isPasswordValid = await passwordUtil.verifyPassword(
            user.password_hash,
            password
        );
        if (!isPasswordValid) {
            throw createError("UNAUTHORIZED", "Invalid credentials");
        }

        // 3. Handle 2FA if enabled
        if (user.mfa_enabled) {
            let is2FAValid = false;

            if (totp) {
                const totpVerificationResult = await verifyTOTP2FA(
                    user.id,
                    totp
                );
                is2FAValid = totpVerificationResult.success;
            } else if (backupCode) {
                // If a backup code is provided, we use the specific function that invalidates it after use.
                const backupCodeVerificationResult = await verifyBackupCode2FA(
                    user.id,
                    backupCode
                );
                is2FAValid = backupCodeVerificationResult.success;
            }

            if (!is2FAValid) {
                throw createError("UNAUTHORIZED", "2FA required or invalid");
            }
        }

        // 4. Create a new session and generate tokens
        const { session, refreshToken, opaqueToken } =
            await sessionsUtil.createSession(client, user.id);
        const accessToken = tokensUtil.generateAccessToken(user);

        await client.query("COMMIT");

        return {
            userId: user.id,
            accessToken,
            refreshToken,
            opaqueToken,
            sessionId: session.id,
        };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during login",
            error
        );
    } finally {
        client.release();
    }
}

async function logoutUser(sessionId) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // Use the utility function to revoke the session
        const revokedSession = await sessionsUtil.revokeSession(
            client,
            sessionId,
            "logout"
        );

        if (!revokedSession) {
            // If the session is not found or already revoked, treat it as a success for security reasons
            await client.query("ROLLBACK"); // Or commit an empty transaction.
            return { message: "Logged out" };
        }

        await client.query("COMMIT");

        return { message: "Logged out" };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.custom_code) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during logout",
            error
        );
    } finally {
        client.release();
    }
}

async function refreshAccessToken(refreshToken, opaqueToken) {
    const client = await db.pool.connect();
    try {
        await client.query("BEGIN");

        // 1. Verify the JWT refresh token to get the session ID.
        const decoded = tokensUtil.verifyRefreshToken(refreshToken);

        if (!decoded || !decoded.sid) {
            throw createError("UNAUTHORIZED", "Invalid refresh token");
        }

        // 2. Verify the session using the session ID and opaque token.
        // This function will also check for token expiration and revocation.
        const session = await sessionsUtil.verifySession(
            client,
            decoded.sid,
            opaqueToken
        );

        if (!session) {
            throw createError("UNAUTHORIZED", "Session invalid");
        }

        // 3. Fetch the user associated with the session.
        const userQuery = `
            SELECT id, tenant_id, email, role, mfa_enabled, is_active FROM users
            WHERE id = $1 AND tenant_id = $2
        `;
        const userResult = await client.query(userQuery, [
            session.user_id,
            session.tenant_id,
        ]);
        const user = userResult.rows[0];

        if (!user || !user.is_active) {
            throw createError("UNAUTHORIZED", "User not found or is inactive");
        }

        // 4. Generate a new access token.
        const newAccessToken = tokensUtil.generateAccessToken(user);

        // 5. Optionally, you can implement refresh token rotation here
        // by generating a new refresh token and invalidating the old one.
        // This is a more advanced security practice.

        await client.query("COMMIT");

        return { accessToken: newAccessToken };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during token refresh",
            error
        );
    } finally {
        client.release();
    }
}

async function enable2FA(userId, totp) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        // Fetch the user's current 2FA secret
        const userQuery =
            "SELECT mfa_enabled, mfa_secret FROM users WHERE id = $1 AND tenant_id = $2";
        const userResult = await client.query(userQuery, [userId, tenantId]);
        const user = userResult.rows[0];

        if (!user) {
            throw createError("NOT_FOUND", "User not found");
        }

        // Check if 2FA is already enabled.
        if (user.mfa_enabled) {
            throw createError(
                "BAD_REQUEST",
                "2FA is already enabled for this user"
            );
        }

        if (!user.mfa_secret) {
            throw createError("BAD_REQUEST", "2FA setup not initiated");
        }

        // Verify the provided OTP against the secret
        const isValid = twofaUtil.verifyTOTP(user.mfa_secret, totp);
        if (!isValid) {
            throw createError("UNAUTHORIZED", "Invalid OTP");
        }

        // Update the user record to enable 2FA
        const updateQuery = `
            UPDATE users SET mfa_enabled = TRUE, updated_at = $1 WHERE id = $2 AND tenant_id = $3
        `;
        await client.query(updateQuery, [getUTCDateTime(), userId, tenantId]);

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

async function disable2FA(userId, totp) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        // Fetch the user's current 2FA status and secret
        const userQuery =
            "SELECT mfa_enabled, mfa_secret, mfa_backup_codes_hash FROM users WHERE id = $1 AND tenant_id = $2";
        const userResult = await client.query(userQuery, [userId, tenantId]);
        const user = userResult.rows[0];

        if (!user) {
            throw createError("NOT_FOUND", "User not found");
        }

        // Check if 2FA is already enabled.
        if (!user.mfa_enabled) {
            throw createError(
                "BAD_REQUEST",
                "2FA is not enabled for this user"
            );
        }

        // Verify the provided OTP
        const isValid = twofaUtil.verifyTOTP(user.mfa_secret, totp);
        if (!isValid) {
            throw createError("UNAUTHORIZED", "Invalid OTP");
        }

        // Update the user record to disable 2FA
        const updateQuery = `
            UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL, mfa_backup_codes_hash = '{}', updated_at = $1 WHERE id = $2 AND tenant_id = $3
        `;
        await client.query(updateQuery, [getUTCDateTime(), userId, tenantId]);

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
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN"); // Start a transaction

        // 1. Fetch user to get their email and check if 2FA is already enabled.
        const userQuery =
            "SELECT email, password_hash, mfa_enabled FROM users WHERE id = $1 AND tenant_id = $2";
        const userResult = await client.query(userQuery, [userId, tenantId]);
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
            "UPDATE users SET mfa_secret = $1 WHERE id = $2 AND tenant_id = $3 RETURNING mfa_secret;";
        await client.query(updateQuery, [base32, userId, tenantId]);

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

async function verifyTOTP2FA(userId, totp) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        // No transaction needed, as this is a read-only operation.

        // 1. Fetch the user's mfa_secret
        const userQuery =
            "SELECT mfa_secret FROM users WHERE id = $1 AND tenant_id = $2";
        const userResult = await client.query(userQuery, [userId, tenantId]);
        const user = userResult.rows[0];

        if (!user || !user.mfa_secret) {
            throw createError(
                "BAD_REQUEST",
                "2FA not configured for this user"
            );
        }

        // 2. Verify the TOTP code.
        const isValid = twofaUtil.verifyTOTP(user.mfa_secret, totp);

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

async function verifyBackupCode2FA(userId, backupCode) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        // 1. Fetch user's hashed backup codes
        const userQuery = `SELECT mfa_backup_codes_hash FROM users WHERE id = $1 AND tenant_id = $2;`;
        const userResult = await client.query(userQuery, [userId, tenantId]);
        const user = userResult.rows[0];

        if (!user || user.mfa_backup_codes_hash.length === 0) {
            throw createError(
                "BAD_REQUEST",
                "No backup codes found for this user"
            );
        }

        // 2. Find the backup code that matches
        let isMatch = false;
        let matchedIndex = -1;
        for (let i = 0; i < user.mfa_backup_codes_hash.length; i++) {
            const isValid = await passwordUtil.verifyPassword(
                user.mfa_backup_codes_hash[i],
                backupCode
            );
            if (isValid) {
                isMatch = true;
                matchedIndex = i;
                break;
            }
        }

        if (!isMatch) {
            await client.query("ROLLBACK");
            throw createError("BAD_REQUEST", "Invalid Backup Codes");
        }

        // 3. Invalidate the backup code by removing it from the array
        const newBackupCodes = user.mfa_backup_codes_hash.filter(
            (_, index) => index !== matchedIndex
        );
        const updateQuery = `
            UPDATE users
            SET mfa_backup_codes_hash = $1, updated_at = $2
            WHERE id = $3 AND tenant_id = $4
            RETURNING mfa_backup_codes_hash;
        `;
        const updateValues = [
            newBackupCodes,
            getUTCDateTime(),
            userId,
            tenantId,
        ];
        const updatedUserResult = await client.query(updateQuery, updateValues);

        await client.query("COMMIT");

        const codesRemaining =
            updatedUserResult.rows[0].mfa_backup_codes_hash.length;
        return { success: true, codesRemaining };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during backup code verification",
            error
        );
    } finally {
        client.release();
    }
}

async function refresh2FABackupCodes(userId, password, totp, backupCode) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        // 1. Fetch user data
        const userQuery = `SELECT password_hash, mfa_enabled, mfa_backup_codes_hash FROM users WHERE id = $1 AND tenant_id = $2;`;
        const userResult = await client.query(userQuery, [userId, tenantId]);
        const user = userResult.rows[0];

        if (!user) {
            throw createError("NOT_FOUND", "User not found");
        }

        if (!user.mfa_enabled) {
            throw createError(
                "BAD_REQUEST",
                "2FA is not enabled for this user"
            );
        }

        // 2. Authenticate the user with either password or existing 2FA proof
        const isPasswordValid = await passwordUtil.verifyPassword(
            user.password_hash,
            password
        );

        let is2FAValid = false;
        if (totp) {
            // Assume verifyTOTP is a service function that fetches the mfa_secret and validates the totp code
            const totpVerificationResult = await verifyTOTP2FA(userId, totp);
            is2FAValid = totpVerificationResult.success;
        } else if (backupCode) {
            // Assume verifyBackupCode is a function that checks the provided backup code against the hashes
            is2FAValid = await twofaUtil.verifyBackupCode(
                backupCode,
                user.mfa_backup_codes_hash
            );
        }

        if (!isPasswordValid || !is2FAValid) {
            throw createError("UNAUTHORIZED", "Invalid password or 2FA proof");
        }

        // 3. Generate new backup codes and hashes
        const { codes, hashes } = await twofaUtil.generateBackupCodes();

        // 4. Update the user record with the new hashed backup codes
        const updateQuery = `
            UPDATE users
            SET mfa_backup_codes_hash = $1, updated_at = $2
            WHERE id = $3 AND tenant_id = $4;
        `;
        const updateValues = [hashes, getUTCDateTime(), userId, tenantId];
        await client.query(updateQuery, updateValues);

        await client.query("COMMIT");

        return {
            message: "Backup codes regenerated successfully",
            backupCodes: codes,
        };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error during backup code refresh",
            error
        );
    } finally {
        client.release();
    }
}

async function getProfile(userId) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        // Fetch user data from the users table.
        const userQuery = `
            SELECT id, email, role, mfa_enabled FROM users
            WHERE id = $1 AND tenant_id = $2 AND is_active = TRUE;
        `;
        const userResult = await client.query(userQuery, [userId, tenantId]);
        const user = userResult.rows[0];

        if (!user) {
            throw createError("NOT_FOUND", "User not found or is inactive");
        }

        // Fetch profile data from the user_profiles table.
        const profileQuery = `
            SELECT profile_data FROM user_profiles
            WHERE user_id = $1 AND tenant_id = $2;
        `;
        const profileResult = await client.query(profileQuery, [
            userId,
            tenantId,
        ]);
        const profile = profileResult.rows[0];

        // Combine user and profile data.
        return {
            user_id: user.id,
            email: user.email,
            role: user.role,
            mfa_enabled: user.mfa_enabled,
            profile_data: profile ? profile.profile_data : {},
        };
    } catch (error) {
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error while fetching user profile",
            error
        );
    } finally {
        client.release();
    }
}

async function updateUserRole(targetUserId, newRole) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        await client.query("BEGIN");

        const VALID_ROLES = await rolesUtil.getValidRoles();

        // 1. Validate that the new role is a valid role
        if (!VALID_ROLES.includes(newRole)) {
            throw createError("BAD_REQUEST", "Invalid role specified");
        }

        // 2. Check if the user exists
        const userExistsQuery =
            "SELECT id FROM users WHERE id = $1 AND tenant_id = $2;";
        const userExistsResult = await client.query(userExistsQuery, [
            targetUserId,
            tenantId,
        ]);
        const userExists = userExistsResult.rows.length > 0;

        if (!userExists) {
            throw createError("NOT_FOUND", "User not found");
        }

        // 3. Update the user's role
        const updateQuery = `
            UPDATE users
            SET role = $1, updated_at = $2
            WHERE id = $3 AND tenant_id = $4
        `;
        const updateValues = [
            newRole,
            getUTCDateTime(),
            targetUserId,
            tenantId,
        ];
        await client.query(updateQuery, updateValues);

        await client.query("COMMIT");

        return {
            message: `User role for ${targetUserId} updated to ${newRole}`,
        };
    } catch (error) {
        await client.query("ROLLBACK");
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error while updating user role",
            error
        );
    } finally {
        client.release();
    }
}

module.exports = {
    registerUser,
    verifyMail,
    resendOtp,
    loginUser,
    logoutUser,
    refreshAccessToken,
    enable2FA,
    disable2FA,
    setup2FA,
    verifyTOTP2FA,
    verifyBackupCode2FA,
    refresh2FABackupCodes,
    updateUserRole,
    getProfile,
};
