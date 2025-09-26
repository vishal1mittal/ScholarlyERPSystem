const express = require("express");
const loggingMiddleware = require("./Logging/loggingMiddleware");
const errorHandler = require("./Logging/errorLoggerMiddleware");
const authRoutes = require("./AuthSVC/Routes/authRoutes");
const tenantRoutes = require("./TenantSVC/Routes/tenantRoutes");
const studentRoutes = require("./StudentSVC/Routes/studentRoutes");
const facultyRoutes = require("./FacultySVC/Routes/facultyRoutes");
const placementRoutes = require("./PlacementsSVC/Routes/placementRoutes");
const eventRoutes = require("./EventSVC/Routes/eventRoutes");
const libraryRoutes = require("./LibrarySVC/Routes/libraryRoutes");
const { swaggerUi, swaggerSpec } = require("./swagger"); // add this

require("dotenv").config();

const app = express();
app.use(express.json()); // Middleware to parse JSON request bodies
app.use(loggingMiddleware);
// Swagger route
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Mount the tenant routes under the /api/tenants base path
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/tenants", tenantRoutes);
app.use("/api/v1/students", studentRoutes);
app.use("/api/v1/faculties", facultyRoutes);
app.use("/api/v1/placements", placementRoutes);
app.use("/api/v1/events", eventRoutes);
app.use("/api/v1/library", libraryRoutes);

app.use(errorHandler);

app.listen(process.env.SERVER_PORT || 3001, () => {
    console.log(
        `Server running on http://localhost:${process.env.SERVER_PORT || 3001}`
    );
    console.log("Swagger docs at http://localhost:3001/api-docs");
});
