// swagger.js (or wherever you define swagger config)
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const options = {
    definition: {
        openapi: "3.0.0",
        info: {
            title: "Scholarly API Docs",
            version: "1.0.0",
            description: "Interactive API documentation with Swagger UI",
        },
        servers: [
            {
                url: "http://localhost:3001/api/v1", // adjust to your base path
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT", // just for UI hints
                },
            },
        },
        security: [
            {
                bearerAuth: [], // apply globally by default
            },
        ],
    },
    apis: ["./AuthSVC/Routes/*.js", "./TenantSVC/Routes/*.js"], // path to your JSDoc comments
};

const swaggerSpec = swaggerJsdoc(options);

module.exports = { swaggerSpec, swaggerUi };
