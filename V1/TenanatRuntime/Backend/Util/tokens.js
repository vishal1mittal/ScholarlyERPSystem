const jwt = require("jsonwebtoken");

function generateAccessToken(user) {
    return jwt.sign(
        {
            uid: user._id.toString(),
            roles: user.roles,
            auth_ver: user.auth_ver,
        },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: "5m" }
    );
}

function generateRefreshToken(sessionId) {
    return jwt.sign({ sid: sessionId }, process.env.JWT_REFRESH_SECRET, {
        expiresIn: "7d",
    });
}

function verifyToken(token, secret) {
    try {
        return jwt.verify(token, secret);
    } catch {
        return null;
    }
}

module.exports = {
    generateAccessToken,
    generateRefreshToken,
    verifyToken,
};
