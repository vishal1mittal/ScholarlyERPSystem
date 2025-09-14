const express = require("express");
const router = express.Router();
const tenantController = require("../Controllers/tenantController"); // Correct import path

router.post("/test-insert-tenant", tenantController.createTenantController);

module.exports = router;
