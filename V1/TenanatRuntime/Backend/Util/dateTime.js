function getUTCDateTime(date = null) {
    // If a date object or a timestamp is provided, return its ISO string.
    if (date) {
        // We handle both Date objects and timestamps (numbers)
        if (typeof date === "number") {
            return new Date(date).toISOString();
        }
        return date.toISOString();
    }
    // Otherwise, return the current UTC date as an ISO string.
    return new Date().toISOString();
}
function getLocalDateTime(date = null) {
    // If a date object or a timestamp is provided, return its ISO string.
    if (date) {
        // We handle both Date objects and timestamps (numbers)
        if (typeof date === "number") {
            return new Date(date).toLocaleString("en-IN", { hour12: true });
        }
        return date.toLocaleString("en-IN", { hour12: true });
    }
    // Otherwise, return the current UTC date as an ISO string.
    return new Date().toLocaleString("en-IN", { hour12: true });
}

module.exports = { getUTCDateTime, getLocalDateTime };
