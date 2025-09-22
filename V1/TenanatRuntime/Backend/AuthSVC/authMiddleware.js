const jwt = require("jsonwebtoken");
const db = require("../DB/db"); // Import our database module
const { createError } = require("../Error/CustomErrorHandler");
const tokensUtil = require("../Util/tokens");
const rolesUtil = require("../Util/roles");
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
        return next(createError("UNAUTHORIZED", "No access token provided."));
    }

    try {
        const payload = tokensUtil.verifyAccessToken(token);
        const userQuery = `
            SELECT
                u.id, u.email, r.name AS role, u.mfa_enabled, u.is_active
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.id = $1 AND u.tenant_id = $2;
        `;
        const userResult = await db.query(userQuery, [
            payload.userId,
            payload.tenantId,
        ]);
        const user = userResult.rows[0];

        if (!user || !user.is_active) {
            return next(
                createError(
                    "UNAUTHORIZED",
                    "User not found or is inactive.",
                    new Error("User not found or is inactive.")
                )
            );
        }

        // The report specifies that the access token should be short-lived, so we don't need to check
        // for an auth_ver mismatch. A token is valid until it expires.

        req.user = {
            id: user.id,
            tenantId: payload.tenantId,
            role: user.role,
            mfa_enabled: user.mfa_enabled,
        };

        next();
    } catch (error) {
        return next(
            createError(
                "UNAUTHORIZED",
                "Invalid or expired Access token.",
                error
            )
        );
    }
}

/**
 * Middleware to authorize a user based on their role.
 * It checks if the authenticated user's role is included in the list of allowed roles.
 */
function authorize(requiredPermission) {
    return async (req, res, next) => {
        if (!req.user) {
            return next(
                createError(
                    "UNAUTHORIZED",
                    "Not authenticated or missing role.",
                    new Error("Not authenticated or missing role.")
                )
            );
        }

        const userId = req.user.id;
        const tenantId = req.user.tenantId;

        try {
            const userPermissions = await rolesUtil.getUserPermissions(
                userId,
                tenantId
            );

            // console.log(userPermissions, requiredPermission);

            if (!userPermissions.has(requiredPermission)) {
                return next(
                    createError(
                        "FORBIDDEN",
                        "You do not have the required permissions.",
                        new Error("You do not have the required permissions.")
                    )
                );
            }

            next();
        } catch (error) {
            return next(
                createError(
                    "INTERNAL_SERVER_ERROR",
                    "Error during authorization check.",
                    error
                )
            );
        }
    };
}

module.exports = {
    authenticate,
    authorize,
};
