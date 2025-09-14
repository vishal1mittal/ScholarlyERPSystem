class CustomError extends Error {
    constructor(errorCode, customMessage) {
        const errorDetails =
            errorMap[errorCode] || errorMap.INTERNAL_SERVER_ERROR;
        super(customMessage || errorDetails.message);

        this.httpStatus = errorDetails.httpStatus;
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

    // Custom internal errors
    "AUTH-401": { httpStatus: 401, message: "Invalid Credentials" },
    "AUTH-409": { httpStatus: 409, message: "Email Already Exists" },
    "STUDENT-404": { httpStatus: 404, message: "Student Not Found" },
    "DB-100": { httpStatus: 500, message: "Database Connection Failed" },
    "DB-101": { httpStatus: 500, message: "Database Query Error" },
};

/**
 * Factory to create a standardized CustomError
 */
function createError(errorCode, customMessage) {
    return formatErrorResponse(new CustomError(errorCode, customMessage));
}

/**
 * Converts error to JSON response
 */
function formatErrorResponse(err) {
    return {
        code: err.errorCode || "INTERNAL_SERVER_ERROR",
        httpStatus: err.httpStatus || 500,
        message: err.message || "Internal Server Error",
    };
}

module.exports = createError;
