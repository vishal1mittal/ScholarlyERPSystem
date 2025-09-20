const crypto = require("crypto");
const { getUTCDateTime } = require("../Util/dateTime");
const tokensUtil = require("./tokens");
const passwordsUtil = require("./password");

async function createSession(client, userId) {
    const sessionId = crypto.randomUUID();
    const opaqueToken = crypto.randomUUID();
    const refreshHash = await passwordsUtil.hashPassword(opaqueToken); // Hash an opaque token
    const expiresAt = getUTCDateTime(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7-day lifetime

    const query = `
        INSERT INTO sessions (id, user_id, tenant_id, refresh_token_hash, created_at, updated_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $5, $6)
        RETURNING *;
    `;
    const values = [
        sessionId,
        userId,
        process.env.TENANT_ID,
        refreshHash,
        getUTCDateTime(),
        expiresAt,
    ];

    try {
        const result = await client.query(query, values);
        return {
            session: result.rows[0],
            refreshToken: tokensUtil.generateRefreshToken(sessionId),
            opaqueToken: opaqueToken,
        };
    } catch (error) {
        throw new Error(error);
    }
}

async function verifySession(client, sessionId, opaqueToken) {
    const query = `
        SELECT user_id, tenant_id, refresh_token_hash FROM sessions
        WHERE id = $1 AND expires_at > $2 AND revoked_at IS NULL
    `;
    const result = await client.query(query, [sessionId, getUTCDateTime()]);

    const session = result.rows[0];

    if (!session) return null;

    const ok = await passwordsUtil.verifyPassword(
        session.refresh_token_hash,
        opaqueToken
    );

    if (!ok) return null;

    return {
        user_id: session.user_id,
        tenant_id: session.tenant_id,
    };
}

async function revokeSession(client, sessionId, reason = "manual") {
    const query = `UPDATE sessions SET revoked_at = $3, revoked_reason = $2, updated_at = $3 WHERE id = $1 RETURNING *`;
    const result = await client.query(query, [
        sessionId,
        reason,
        getUTCDateTime(),
    ]);
    return result.rows[0];
}

module.exports = {
    createSession,
    verifySession,
    revokeSession,
};
