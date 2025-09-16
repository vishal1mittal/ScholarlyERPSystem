const fs = require("fs");
const path = require("path");
const { getUTCDateTime, getLocalDateTime } = require("../Util/dateTime");

function loggingMiddleware(req, res, next) {
    const dateStr = getUTCDateTime().slice(0, 10);
    const logFile = path.join(__dirname, `request_logs_${dateStr}.ndjson`);

    const requestLog = {
        timestamp_utc: getUTCDateTime(),
        timestamp_local: getLocalDateTime(),
        request: {
            method: req.method,
            route: req.originalUrl,
            body: req.body,
        },
        response: {},
    };

    // 🔹 Attach to req so errorLoggerMiddleware can add errors
    req._requestLog = requestLog;

    const originalJson = res.json;
    res.json = function (data) {
        requestLog.response = {
            status: res.statusCode,
            body: data,
        };
        return originalJson.apply(res, arguments);
    };

    const originalSend = res.send;
    res.send = function (data) {
        if (
            !res.get("Content-Type") ||
            !res.get("Content-Type").includes("application/json")
        ) {
            requestLog.response = {
                status: res.statusCode,
                body: data,
            };
        }
        return originalSend.apply(res, arguments);
    };

    // 🔹 Write once, after response (or error) finishes
    res.on("finish", () => {
        if (!req._hasError) {
            saveLog(logFile, requestLog);
        }
    });

    next();
}

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

module.exports = loggingMiddleware;
