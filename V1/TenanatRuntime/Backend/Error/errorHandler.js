class CustomError extends Error {
    constructor(message, httpStatus, errorCode) {
        super(message);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
        this.name = this.constructor.name;
        Error.captureStackTrace(this, this.constructor);
    }
}

const errorMap = {
    // Universal HTTP errors
    BAD_REQUEST: { httpStatus: 400, message: "Bad Request" },
    UNAUTHORIZED: { httpStatus: 401, message: "Unauthorized" },
    FORBIDDEN: { httpStatus: 403, message: "Forbidden" },
    NOT_FOUND: { httpStatus: 404, message: "Not Found" },
    INTERNAL_SERVER_ERROR: {
        httpStatus: 500,
        message: "Internal Server Error",
    },

    // Custom internal errors for specific modules (as per the report)
    "AUTH-401": { httpStatus: 401, message: "Invalid Credentials" },
    "AUTH-409": { httpStatus: 409, message: "Email Already Exists" },
    "STUDENT-404": { httpStatus: 404, message: "Student Not Found" },
    "DB-100": { httpStatus: 500, message: "Database Connection Failed" },
    "DB-101": { httpStatus: 500, message: "Database Query Error" },
};

/**
 * Creates a standardized error response object.
 * @param {string} errorCode - The custom internal error code (e.g., 'AUTH-401').
 * @param {string} [customMessage] - An optional message to override the default.
 * @returns {object} The standardized error response.
 */
function createErrorResponse(errorCode, customMessage) {
    const errorDetails = errorMap[errorCode] || errorMap.INTERNAL_SERVER_ERROR;
    return {
        code: errorCode,
        httpStatus: errorDetails.httpStatus,
        message: customMessage || errorDetails.message,
    };
}

module.exports = {
    CustomError,
    createErrorResponse,
    errorMap,
};
