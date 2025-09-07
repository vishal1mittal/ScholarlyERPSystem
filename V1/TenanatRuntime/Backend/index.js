const express = require("express");
const db = require("./DB/db"); // Import our database module

const app = express();

app.use(express.json()); // Middleware to parse JSON request bodies

app.get("/users", async (req, res) => {
    try {
        const result = await db.query("SELECT id FROM tenants");
        res.status(200).json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/test-insert-tenant", async (req, res) => {
    try {
        const newTenantId = "2db3c240-f9b7-4a89-bf12-339bfcd289b9";
        const queryText = "INSERT INTO tenants(id) VALUES($1) RETURNING id";
        const result = await db.query(queryText, [newTenantId]);

        res.status(201).json({
            message: "Tenant added successfully for testing.",
            tenant_id: result.rows[0].id,
        });
    } catch (err) {
        console.error("Error during test insertion:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.listen(process.env.SERVER_PORT || 3001, () => {
    console.log(
        `Server running on http://localhost:${process.env.SERVER_PORT || 3001}`
    );
});
