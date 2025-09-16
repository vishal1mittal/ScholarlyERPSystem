const tenantServices = require("../Services/tenantServices");
const { createError } = require("../../Error/CustomErrorHandler");
const crypto = require("crypto");

async function createTenantController(req, res, next) {
    const uuid = crypto.randomUUID();

    try {
        const tenant = await tenantServices.createTenant(uuid);
        res.status(201).json({
            message: "Tenant added successfully for testing.",
            tenant_id: tenant.id,
        });
    } catch (err) {
        next(
            createError(
                "NOT_ACCEPTABLE",
                "User ID Invalid or Already Exists",
                err
            )
        );
    }
}

module.exports = { createTenantController };
