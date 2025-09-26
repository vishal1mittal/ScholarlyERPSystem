const { createError } = require("../../Error/CustomErrorHandler");
const studentService = require("../Services/studentService");
const feildValidator = require("../../Util/feildValidator");
const rolesUtil = require("../../Util/roles");

async function getStudents(req, res, next) {
    const { page, limit, search } = req.query;
    const userId = req.user.id;

    // 1. Granular Authorization Check
    // The documents state this is available to ADMIN or FACULTY.
    // The required permission is the ability to view a list of users/students.
    const hasPermission = await rolesUtil.checkRoleSpecificPermission(
        userId,
        userId,
        null, // No target user ID needed for list view
        "list_all_students", // General permission name
        false // don't need role prefix
    );

    if (!hasPermission) {
        return next(
            createError(
                "FORBIDDEN",
                "You do not have permission to view the student directory."
            )
        );
    }

    // 2. Input Validation (Basic sanity check)
    if (limit && isNaN(parseInt(limit))) {
        return next(createError("BAD_REQUEST", "Limit must be a number."));
    }
    if (page && isNaN(parseInt(page))) {
        return next(createError("BAD_REQUEST", "Page must be a number."));
    }

    try {
        const studentData = await studentService.getStudents(
            page,
            limit,
            search
        );

        // 3. Send the Response
        return res.status(200).json(studentData); // 200 OK for a successful read
    } catch (err) {
        return next(err);
    }
}

module.exports = { getStudents };
