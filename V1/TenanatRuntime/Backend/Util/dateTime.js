function getUTCDateTime() {
    return new Date().toISOString();
}
function getLocalDateTime() {
    return new Date().toLocaleString("en-IN", { hour12: true });
}

module.exports = { getUTCDateTime, getLocalDateTime };
