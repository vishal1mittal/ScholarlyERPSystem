const jwt = require("jsonwebtoken");
const db = require("./DB/db"); // Import our database module
const createError = require("../Error/CustomErrorHandler");
require("dotenv").config();

/**
 * Middleware to authenticate a user by verifying a JWT access token.
 * It checks the token's validity, ensures the user exists, and attaches
 * the user's information to the request object.
 */
async function authenticate(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res
            .status(401)
            .json(createError("UNAUTHORIZED", "No token provided."));
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

        const userQuery = `
            SELECT id, email, role, mfa_enabled, is_active FROM users
            WHERE id = $1 AND tenant_id = $2
        `;
        const userResult = await db.query(userQuery, [
            payload.id,
            payload.tenant_id,
        ]);
        const user = userResult.rows[0];

        if (!user || !user.is_active) {
            return res
                .status(401)
                .json(
                    createError(
                        "UNAUTHORIZED",
                        "User not found or is inactive."
                    )
                );
        }

        // The report specifies that the access token should be short-lived, so we don't need to check
        // for an auth_ver mismatch. A token is valid until it expires.

        req.user = {
            id: user.id,
            tenantId: payload.tenant_id,
            role: user.role,
            mfa_enabled: user.mfa_enabled,
        };
        next();
    } catch (error) {
        return res
            .status(401)
            .json(createError("UNAUTHORIZED", "Invalid or expired token."));
    }
}

/**
 * Middleware to authorize a user based on their role.
 * It checks if the authenticated user's role is included in the list of allowed roles.
 */
function authorize(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !req.user.role) {
            return res
                .status(403)
                .json(
                    createError(
                        "FORBIDDEN",
                        "Not authenticated or missing role."
                    )
                );
        }

        if (allowedRoles.includes(req.user.role)) {
            next();
        } else {
            return res
                .status(403)
                .json(
                    createError(
                        "FORBIDDEN",
                        "You do not have the required permissions."
                    )
                );
        }
    };
}

module.exports = {
    authenticate,
    authorize,
};
