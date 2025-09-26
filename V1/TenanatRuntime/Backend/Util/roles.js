const db = require("../DB/db");
const { createError } = require("../Error/CustomErrorHandler");

async function getValidRoles() {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        const query = `
            SELECT id, name
            FROM roles
            WHERE tenant_id = $1
            ORDER BY name;
        `;
        const result = await client.query(query, [tenantId]);

        if (result.rows.length === 0) {
            throw createError("NOT_FOUND", "No roles found for this tenant");
        }

        // Map the result into an object for easy lookup
        const roles = result.rows.reduce((acc, row) => {
            acc[row.name] = row.id;
            return acc;
        }, {});

        return roles;
    } catch (error) {
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error while fetching roles",
            error
        );
    } finally {
        client.release();
    }
}

async function getUserPermissions(userId) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        const query = `
            SELECT p.name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE u.id = $1 AND u.tenant_id = $2;
        `;
        const result = await client.query(query, [userId, tenantId]);

        const permissions = new Set(result.rows.map((row) => row.name));
        return permissions;
    } catch (error) {
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error while fetching user permissions",
            error
        );
    } finally {
        client.release();
    }
}

async function getLeastPrivilegedRole() {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        // First, check for a role explicitly marked as the default
        const defaultRoleQuery = `
            SELECT r.id, r.name
            FROM roles r
            JOIN role_permissions rp ON r.id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE r.tenant_id = $1 AND p.name = 'can_register_as_default'
            LIMIT 1;
        `;
        const defaultRoleResult = await client.query(defaultRoleQuery, [
            tenantId,
        ]);
        const defaultRole = defaultRoleResult.rows[0];

        if (defaultRole) {
            return {
                id: defaultRole.id,
                name: defaultRole.name,
            };
        }

        // If no explicit default role is found, fall back to the role with the fewest permissions
        const fallbackRoleQuery = `
            SELECT r.id, r.name
            FROM roles r
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            WHERE r.tenant_id = $1
            GROUP BY r.id
            ORDER BY COUNT(rp.permission_id) ASC
            LIMIT 1;
        `;
        const fallbackRoleResult = await client.query(fallbackRoleQuery, [
            tenantId,
        ]);
        const leastPrivilegedRole = fallbackRoleResult.rows[0];

        if (!leastPrivilegedRole) {
            throw createError(
                "INTERNAL_SERVER_ERROR",
                "Default role not found for tenant."
            );
        }

        return {
            id: leastPrivilegedRole.id,
            name: leastPrivilegedRole.name,
        };
    } catch (error) {
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Internal server error while fetching least privileged role",
            error
        );
    } finally {
        client.release();
    }
}

async function checkRoleUpdatePermissions(actingUserId, newRole) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        // 1. Find the acting user's role ID and name
        const actingUserRoleQuery = `
            SELECT r.id AS role_id, r.name AS role_name FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.id = $1 AND u.tenant_id = $2;
        `;
        const actingUserRoleResult = await client.query(actingUserRoleQuery, [
            actingUserId,
            tenantId,
        ]);
        const actingUser = actingUserRoleResult.rows[0];

        if (!actingUser) {
            return false;
        }

        const actingRoleId = actingUser.role_id;

        // 2. Find the new role's ID
        const newRoleQuery = `
            SELECT id AS role_id FROM roles
            WHERE name = $1 AND tenant_id = $2;
        `;
        const newRoleResult = await client.query(newRoleQuery, [
            newRole,
            tenantId,
        ]);
        const newRoleData = newRoleResult.rows[0];

        if (!newRoleData) {
            return false;
        }

        // 3. Create the permission name dynamically
        const permissionName = `change_role_to_${newRole.toLowerCase()}`;

        // 4. Check if the acting user's role has the specific permission
        const permissionQuery = `
            SELECT 1 FROM role_permissions rp
            JOIN permissions p ON rp.permission_id = p.id
            WHERE rp.role_id = $1 AND p.name = $2;
        `;
        const permissionResult = await client.query(permissionQuery, [
            actingRoleId,
            permissionName,
        ]);

        return permissionResult.rows.length > 0;
    } catch (error) {
        // Log the error but don't throw, as a permission check should return false, not crash the app
        createError(
            "INTERNAL_SERVER_ERROR",
            "Error checking role permissions:",
            error
        );
        return false;
    } finally {
        client.release();
    }
}

// Renamed to be more general
async function checkRoleSpecificPermission(
    userId,
    targetUserId,
    targetRoleName,
    permissionPrefix
) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        // 1. Find the acting user's role ID
        const actingUserRoleQuery = `
            SELECT u.role_id FROM users u
            WHERE u.id = $1 AND u.tenant_id = $2;
        `;
        const actingUserRoleResult = await client.query(actingUserRoleQuery, [
            userId,
            tenantId,
        ]);

        const actingUser = actingUserRoleResult.rows[0];

        if (!actingUser) {
            return false;
        }

        const actingRoleId = actingUser.role_id;

        // 2. Get the TARGET user's CURRENT role Name (The user being affected)
        const targetUserRoleQuery = `
            SELECT r.name AS role_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.id = $1 AND u.tenant_id = $2;
        `;
        const targetUserRoleResult = await client.query(targetUserRoleQuery, [
            targetUserId,
            tenantId,
        ]);
        const targetUserRole = targetUserRoleResult.rows[0]?.role_name;

        if (!targetUserRole) {
            // The target user must exist and have a role to perform an action against them
            return false;
        }
        // 3. Determine the ROLE NAME to check permission against:
        //    - If 'targetRoleName' is provided (e.g., for an update), use it.
        //    - Otherwise, use the 'targetUserRole' (e.g., for deletion).
        const roleToCheck = targetRoleName || targetUserRole;

        const permissionName = `${permissionPrefix}_${roleToCheck.toLowerCase()}`;

        // 4. Check if the acting user's role has the specific permission
        const permissionQuery = `
            SELECT 1 FROM role_permissions rp
            JOIN permissions p ON rp.permission_id = p.id
            WHERE rp.role_id = $1 AND p.name = $2;
        `;

        const permissionResult = await client.query(permissionQuery, [
            actingRoleId,
            permissionName,
        ]);

        return permissionResult.rows.length > 0;
    } catch (error) {
        // Log the error but don't throw, as a permission check should return false, not crash the app
        console.error("Error checking role permissions:", error);
        return false;
    } finally {
        client.release();
    }
}

module.exports = {
    getValidRoles,
    getUserPermissions,
    getLeastPrivilegedRole,
    checkRoleUpdatePermissions,
    checkRoleSpecificPermission,
};
