const db = require("../../DB/db"); // Import our database module

async function createTenant(id) {
    const queryText = "INSERT INTO tenants(id) VALUES($1) RETURNING id";
    const result = await db.query(queryText, [id]);
    return result.rows[0];
}

module.exports = { createTenant };
