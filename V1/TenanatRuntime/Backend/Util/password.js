const argon2 = require("argon2");

async function hashPassword(password) {
    return argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
    });
}

async function verifyPassword(hash, password) {
    return argon2.verify(hash, password);
}

module.exports = {
    hashPassword,
    verifyPassword,
};
