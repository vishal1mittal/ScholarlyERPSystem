const jwt = require("jsonwebtoken");

function generateAccessToken(user) {
    return jwt.sign(
        {
            userId: user.id, // Use 'id' from the user object
            tenantId: user.tenant_id, // Include tenant_id for Row-Level Security
            role: user.role, // Use 'role' from the user object
        },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: "5m" } // Access token lifetime is 5 minutes [cite: 1325, 1324]
    );
}

function generateRefreshToken(sessionId) {
    return jwt.sign(
        {
            sid: sessionId, // 'sid' is the session ID
        },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: "7d" } // Refresh token lifetime is 7 days [cite: 1325, 1324]
    );
}

function verifyRefreshToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    } catch {
        return null;
    }
}

function verifyAccessToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    } catch {
        return null;
    }
}

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken,
    verifyAccessToken,
};
