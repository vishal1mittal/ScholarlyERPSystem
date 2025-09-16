const { v4: uuidv4 } = require("uuid");
const db = require("../DB/db");
const argon2 = require("argon2");
const { getUTCDateTime } = require("../../Util/dateTime");
const tokens = require("./tokens");

async function createSession(userId, tenantId) {
    const sessionId = uuidv4();
    const refreshHash = await argon2.hash(uuidv4()); // Hash an opaque token
    const expiresAt = new Date(
        Date.now() + 7 * 24 * 60 * 60 * 1000
    ).toISOString(); // 7-day lifetime

    const query = `
        INSERT INTO sessions (id, user_id, tenant_id, refresh_token_hash, created_at, updated_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $5, $6)
        RETURNING *;
    `;
    const values = [
        sessionId,
        userId,
        tenantId,
        refreshHash,
        getUTCDateTime(),
        expiresAt,
    ];

    try {
        const result = await db.query(query, values);
        return {
            session: result.rows[0],
            refreshToken: tokens.generateRefreshToken(sessionId),
        };
    } catch (error) {
        return next("INTERNAL_SERVER_ERROR", "Error Creating Session", error);
    }
}

async function verifySession(sessionId, opaqueToken) {
    const query = `SELECT refresh_token_hash FROM sessions WHERE id = $1 AND expires_at > $2 AND revoked_at IS NULL`;
    const result = await db.query(query, [sessionId, getUTCDateTime()]);
    const session = result.rows[0];

    if (!session) return null;

    const ok = await argon2.verify(session.refresh_token_hash, opaqueToken);

    if (!ok) return null;

    return session;
}

async function revokeSession(sessionId, reason = "manual") {
    const query = `UPDATE sessions SET revoked_at = $3, reason = $2, updated_at = $3 WHERE id = $1 RETURNING *`;
    const result = await db.query(query, [sessionId, reason, getUTCDateTime()]);
    return result.rows[0];
}

module.exports = {
    createSession,
    verifySession,
    revokeSession,
};
