// errorLoggerMiddleware.js
const fs = require("fs");
const path = require("path");

function errorLoggerMiddleware(err, req, res, next) {
    if (req._requestLog) {
        req._requestLog.error = {
            message: err.message,
            stack: err.stack ? err.stack.split("\n") : [], // 🔹 split into lines
        };
    }
    next();
}

module.exports = errorLoggerMiddleware;
