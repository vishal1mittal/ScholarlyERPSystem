const db = require("../DB/db");
let localRoles = process.env.LOCAL_ROLES;

async function getValidRoles() {
    if (localRoles) {
        return localRoles;
    }

    try {
        const query = `
            SELECT 
                pg_get_constraintdef(c.oid) as condef
            FROM pg_constraint c
            JOIN pg_class t ON c.conrelid = t.oid
            WHERE c.contype = 'c'
            AND t.relname = 'users'
            AND c.conname = 'user_role_check';
        `;
        const result = await db.query(query);
        const condef = result.rows[0].condef;

        const matches = condef.match(/'([^']+)'/g); // get all 'ITEM'
        const roles = matches.map((item) => item.replace(/'/g, "")); // strip quotes

        return roles;
    } catch (error) {
        throw new Error(error);
    }
}

module.exports = { getValidRoles };
