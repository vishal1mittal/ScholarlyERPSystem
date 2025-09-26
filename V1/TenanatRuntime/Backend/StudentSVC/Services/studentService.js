const db = require("../../DB/db"); // Import our database module
const passwordUtil = require("../../Util/password");
const tokensUtil = require("../../Util/tokens");
const sessionsUtil = require("../../Util/session");
const { getUTCDateTime } = require("../../Util/dateTime");
const { createError } = require("../../Error/CustomErrorHandler");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { otpEmailTemplate } = require("../../Util/emailTemplate"); // Assuming this utility exists
const twofaUtil = require("../../Util/twoFA");
const rolesUtil = require("../../Util/roles");

const DEFAULT_LIMIT = 20;

/**
 * Retrieves a paginated list of student profiles using pg_trgm for fuzzy searching.
 */
async function getStudents(page, limit, search) {
    const client = await db.pool.connect();
    const tenantId = process.env.TENANT_ID;
    try {
        const pageNumber = parseInt(page) || 1;
        const limitNumber = parseInt(limit) || DEFAULT_LIMIT;
        const offset = (pageNumber - 1) * limitNumber;

        let queryValues = [tenantId];
        let searchFilter = "";
        let similarityParamIndex = 0;

        // Base SELECT list for the inner subquery
        const selectFields = `
            s.id AS student_id,
            u.email,
            up.profile_data->>'first_name' AS first_name,
            up.profile_data->>'last_name' AS last_name,
            s.enrollment_date,
            s.profile_data,
            CONCAT_WS(' ', up.profile_data->>'first_name', up.profile_data->>'last_name', u.email) AS search_text
        `;

        // Base FROM/JOIN structure
        const fromJoins = `
            FROM students s
            JOIN users u ON s.user_id = u.id
            JOIN user_profiles up ON u.id = up.user_id
            WHERE s.tenant_id = $1
        `;

        // 1. pg_trgm Fuzzy Search Setup
        if (search) {
            searchFilter = ` AND t.search_text % $2 `;
            queryValues.push(search);
            similarityParamIndex = queryValues.length;
        }

        // --- Execute Count Query ---
        // The COUNT query needs to wrap the entire data generation logic
        const countQuery = `
            SELECT COUNT(t.student_id)
            FROM (
                SELECT ${selectFields} ${fromJoins}
            ) AS t
            WHERE t.student_id IS NOT NULL ${searchFilter};
        `;
        const totalResult = await client.query(countQuery, queryValues);
        const totalRecords = parseInt(totalResult.rows[0].count);

        // 2. Main Data Query with Sorting and Pagination
        const limitParamIndex = queryValues.length + 1;
        const offsetParamIndex = queryValues.length + 2;

        const dataQuery = `
            SELECT *
            FROM (
                SELECT ${selectFields} ${fromJoins}
            ) AS t
            WHERE t.student_id IS NOT NULL ${searchFilter}
            ORDER BY 
                ${
                    search
                        ? `SIMILARITY(t.search_text, $${similarityParamIndex}) DESC,`
                        : ""
                } 
                t.email ASC
            LIMIT $${limitParamIndex} OFFSET $${offsetParamIndex};
        `;

        // Values for LIMIT and OFFSET are added at the end
        const dataValues = queryValues.concat([limitNumber, offset]);

        const studentsResult = await client.query(dataQuery, dataValues);
        const students = studentsResult.rows;

        return {
            students,
            pagination: {
                total_records: totalRecords,
                page: pageNumber,
                limit: limitNumber,
                total_pages: Math.ceil(totalRecords / limitNumber),
            },
        };
    } catch (error) {
        if (error.errorCode) throw error;
        throw createError(
            "INTERNAL_SERVER_ERROR",
            "Error fetching student list.",
            error
        );
    } finally {
        client.release();
    }
}

module.exports = { getStudents };
