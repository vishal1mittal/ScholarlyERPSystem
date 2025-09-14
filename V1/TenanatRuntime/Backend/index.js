const express = require("express");
const loggingMiddleware = require("./Logging/loggingMiddleware");
const errorLoggerMiddleware = require("./Logging/errorLoggerMiddleware");
const createError = require("./Error/CustomErrorHandler");
const tenantRoutes = require("./TenantSVC/Routes/tenantRoutes");

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies
app.use(loggingMiddleware);

// Mount the tenant routes under the /api/tenants base path
app.use("/api/v1/tenants", tenantRoutes);

app.use(errorLoggerMiddleware);
app.listen(process.env.SERVER_PORT || 3001, () => {
    console.log(
        `Server running on http://localhost:${process.env.SERVER_PORT || 3001}`
    );
});
