const tenantServices = require("../Services/tenantServices"); // Correct import path

const createError = require("../../Error/CustomErrorHandler");
async function createTenantController(req, res, next) {
    const { uuid } = req.body;
    const id = uuid || uuidv4();

    try {
        const tenant = await tenantServices.createTenant(id);
        res.status(201).json({
            message: "Tenant added successfully for testing.",
            tenant_id: tenant.id,
        });
    } catch (err) {
        res.status(500).json(createError("INTERNAL_SERVER_ERROR"));
        next(err);
    }
}

module.exports = { createTenantController };
