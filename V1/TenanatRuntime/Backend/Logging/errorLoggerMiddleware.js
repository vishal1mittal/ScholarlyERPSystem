const { CustomError } = require("../Error/CustomErrorHandler");
const fs = require("fs");
const path = require("path");

const errorHandler = (err, req, res, next) => {
    const dateStr = new Date().toISOString().slice(0, 10);
    const logFile = path.join(__dirname, `request_logs_${dateStr}.ndjson`);
    const now = new Date();

    const statusCode = err instanceof CustomError ? err.httpStatus : 500;

    // Response sent to client
    const responseBody = {
        code:
            err instanceof CustomError
                ? err.errorCode
                : "INTERNAL_SERVER_ERROR",
        httpStatus: statusCode,
        message: err.message || "Internal Server Error",
    };

    // Log entry
    const logEntry = {
        timestamp_utc: now.toISOString(),
        timestamp_local: now.toLocaleString("en-IN", { hour12: true }),
        request: {
            method: req.method,
            route: req.originalUrl,
            body: req.body,
        },
        response: {
            status: statusCode,
            body: responseBody,
        },
        error: {
            message: err.cause.message,
            stack: err.cause.stack ? err.cause.stack.split("\n") : [],
        },
    };

    // ✅ Mark request as errored so loggingMiddleware won’t write
    req._hasError = true;

    // 🔹 Write once, after response (or error) finishes
    res.on("finish", () => {
        saveLog(logFile, logEntry);
    });

    next();
    res.status(statusCode).json(responseBody);
};

function saveLog(filePath, logEntry) {
    const entryString = JSON.stringify(logEntry, null, 2) + "\n";

    // Prepend log (newest first)
    if (fs.existsSync(filePath)) {
        const existing = fs.readFileSync(filePath, "utf-8");
        fs.writeFileSync(filePath, entryString + existing, "utf-8");
    } else {
        fs.writeFileSync(filePath, entryString, "utf-8");
    }
}

module.exports = errorHandler;
