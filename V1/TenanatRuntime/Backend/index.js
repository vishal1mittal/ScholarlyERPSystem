const express = require("express");
const db = require("./DB/db"); // Import our database module
const loggingMiddleware = require("./Logging/loggingMiddleware");
const errorLoggerMiddleware = require("./Logging/errorLoggerMiddleware");
const createError = require("./Error/CustomErrorHandler");

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies
app.use(loggingMiddleware);

app.get("/users", async (req, res) => {
    try {
        const result = await db.query("SELECT id FROM tenants");
        res.status(200).json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/test-insert-tenant", async (req, res, next) => {
    var id = req.body.uuid;
    try {
        const newTenantId = id;
        const queryText = "INSERT INTO tenants(id) VALUES($1) RETURNING id";
        const result = await db.query(queryText, [newTenantId]);

        res.status(201).json({
            message: "Tenant added successfully for testing.",
            tenant_id: result.rows[0].id,
        });
    } catch (err) {
        res.status(500).json(createError("INTERNAL_SERVER_ERROR"));
        next(err);
    }
});

app.listen(process.env.SERVER_PORT || 3001, () => {
    console.log(
        `Server running on http://localhost:${process.env.SERVER_PORT || 3001}`
    );
});

app.use(errorLoggerMiddleware);
