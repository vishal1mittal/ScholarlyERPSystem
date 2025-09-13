const fs = require("fs");
const path = require("path");

function loggingMiddleware(req, res, next) {
    const dateStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const logFile = path.join(__dirname, `request_logs_${dateStr}.ndjson`);
    const now = new Date();

    const requestLog = {
        timestamp_utc: now.toISOString(),
        timestamp_local: now.toLocaleString("en-IN", { hour12: true }),
        request: {
            method: req.method,
            route: req.originalUrl,
            body: req.body,
        },
        response: {}, // will be filled later
    };

    const originalJson = res.json;
    res.json = function (data) {
        requestLog.response = {
            status: res.statusCode,
            body: data,
        };
        saveLog(logFile, requestLog);

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
            saveLog(logFile, requestLog);
        }

        return originalSend.apply(res, arguments);
    };

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
