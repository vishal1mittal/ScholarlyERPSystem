const errorMap = {
    // 1xx Informational (rarely used in APIs)
    CONTINUE: { httpStatus: 100, message: "Continue" },
    SWITCHING_PROTOCOLS: { httpStatus: 101, message: "Switching Protocols" },
    PROCESSING: { httpStatus: 102, message: "Processing" },

    // 2xx Success
    OK: { httpStatus: 200, message: "OK" },
    CREATED: { httpStatus: 201, message: "Created" },
    ACCEPTED: { httpStatus: 202, message: "Accepted" },
    NON_AUTHORITATIVE_INFORMATION: {
        httpStatus: 203,
        message: "Non-Authoritative Information",
    },
    NO_CONTENT: { httpStatus: 204, message: "No Content" },
    RESET_CONTENT: { httpStatus: 205, message: "Reset Content" },
    PARTIAL_CONTENT: { httpStatus: 206, message: "Partial Content" },

    // 3xx Redirection
    MULTIPLE_CHOICES: { httpStatus: 300, message: "Multiple Choices" },
    MOVED_PERMANENTLY: { httpStatus: 301, message: "Moved Permanently" },
    FOUND: { httpStatus: 302, message: "Found" },
    SEE_OTHER: { httpStatus: 303, message: "See Other" },
    NOT_MODIFIED: { httpStatus: 304, message: "Not Modified" },
    TEMPORARY_REDIRECT: { httpStatus: 307, message: "Temporary Redirect" },
    PERMANENT_REDIRECT: { httpStatus: 308, message: "Permanent Redirect" },

    // 4xx Client Errors
    BAD_REQUEST: { httpStatus: 400, message: "Bad Request" },
    UNAUTHORIZED: { httpStatus: 401, message: "Unauthorized" },
    PAYMENT_REQUIRED: { httpStatus: 402, message: "Payment Required" },
    FORBIDDEN: { httpStatus: 403, message: "Forbidden" },
    NOT_FOUND: { httpStatus: 404, message: "Not Found" },
    METHOD_NOT_ALLOWED: { httpStatus: 405, message: "Method Not Allowed" },
    NOT_ACCEPTABLE: { httpStatus: 406, message: "Not Acceptable" },
    PROXY_AUTHENTICATION_REQUIRED: {
        httpStatus: 407,
        message: "Proxy Authentication Required",
    },
    REQUEST_TIMEOUT: { httpStatus: 408, message: "Request Timeout" },
    CONFLICT: { httpStatus: 409, message: "Conflict" },
    GONE: { httpStatus: 410, message: "Gone" },
    LENGTH_REQUIRED: { httpStatus: 411, message: "Length Required" },
    PRECONDITION_FAILED: { httpStatus: 412, message: "Precondition Failed" },
    PAYLOAD_TOO_LARGE: { httpStatus: 413, message: "Payload Too Large" },
    URI_TOO_LONG: { httpStatus: 414, message: "URI Too Long" },
    UNSUPPORTED_MEDIA_TYPE: {
        httpStatus: 415,
        message: "Unsupported Media Type",
    },
    RANGE_NOT_SATISFIABLE: {
        httpStatus: 416,
        message: "Range Not Satisfiable",
    },
    EXPECTATION_FAILED: { httpStatus: 417, message: "Expectation Failed" },
    IM_A_TEAPOT: { httpStatus: 418, message: "I'm a teapot" },
    UNPROCESSABLE_ENTITY: { httpStatus: 422, message: "Unprocessable Entity" },
    LOCKED: { httpStatus: 423, message: "Locked" },
    FAILED_DEPENDENCY: { httpStatus: 424, message: "Failed Dependency" },
    TOO_EARLY: { httpStatus: 425, message: "Too Early" },
    UPGRADE_REQUIRED: { httpStatus: 426, message: "Upgrade Required" },
    PRECONDITION_REQUIRED: {
        httpStatus: 428,
        message: "Precondition Required",
    },
    TOO_MANY_REQUESTS: { httpStatus: 429, message: "Too Many Requests" },
    REQUEST_HEADER_FIELDS_TOO_LARGE: {
        httpStatus: 431,
        message: "Request Header Fields Too Large",
    },
    UNAVAILABLE_FOR_LEGAL_REASONS: {
        httpStatus: 451,
        message: "Unavailable For Legal Reasons",
    },

    // 5xx Server Errors
    INTERNAL_SERVER_ERROR: {
        httpStatus: 500,
        message: "Internal Server Error",
    },
    NOT_IMPLEMENTED: { httpStatus: 501, message: "Not Implemented" },
    BAD_GATEWAY: { httpStatus: 502, message: "Bad Gateway" },
    SERVICE_UNAVAILABLE: { httpStatus: 503, message: "Service Unavailable" },
    GATEWAY_TIMEOUT: { httpStatus: 504, message: "Gateway Timeout" },
    HTTP_VERSION_NOT_SUPPORTED: {
        httpStatus: 505,
        message: "HTTP Version Not Supported",
    },
    VARIANT_ALSO_NEGOTIATES: {
        httpStatus: 506,
        message: "Variant Also Negotiates",
    },
    INSUFFICIENT_STORAGE: { httpStatus: 507, message: "Insufficient Storage" },
    LOOP_DETECTED: { httpStatus: 508, message: "Loop Detected" },
    NOT_EXTENDED: { httpStatus: 510, message: "Not Extended" },
    NETWORK_AUTHENTICATION_REQUIRED: {
        httpStatus: 511,
        message: "Network Authentication Required",
    },

    // Custom internal errors (fill as needed)
    "AUTH-401": { httpStatus: 401, message: "Invalid Credentials" },
    "AUTH-409": { httpStatus: 409, message: "Email Already Exists" },
    "STUDENT-404": { httpStatus: 404, message: "Student Not Found" },
    "DB-100": { httpStatus: 500, message: "Database Connection Failed" },
    "DB-101": { httpStatus: 500, message: "Database Query Error" },
};

class CustomError extends Error {
    constructor(errorCode, customMessage, cause) {
        const errorDetails =
            errorMap[errorCode] || errorMap.INTERNAL_SERVER_ERROR;
        super(customMessage || errorDetails.message);

        this.httpStatus = errorDetails.httpStatus;
        this.errorCode = errorCode || "INTERNAL_SERVER_ERROR";
        this.name = this.constructor.name;
        this.cause = cause;
        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Factory to create CustomError instances
 */
function createError(errorCode, customMessage, cause) {
    return new CustomError(errorCode, customMessage, cause);
}

module.exports = { CustomError, createError, errorMap };
