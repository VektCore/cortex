/**
 * Authentication module with JWT and crypto vulnerabilities.
 * CWE-798: Hardcoded Credentials
 * CWE-347: Improper Verification of Cryptographic Signature
 * Severity: CRITICAL
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// VULNERABILITY: Hardcoded JWT secret
const JWT_SECRET = 'super-secret-key-do-not-share';

// VULNERABILITY: Hardcoded API keys
const API_KEYS = {
    admin: 'admin-api-key-12345',
    user: 'user-api-key-67890'
};

// VULNERABILITY: JWT none algorithm attack
function verifyTokenInsecure(token) {
    // BAD: algorithms not specified - allows 'none' algorithm
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (e) {
        return null;
    }
}

// VULNERABILITY: Weak JWT secret
function signTokenWeakSecret(payload) {
    // BAD: Short, predictable secret
    return jwt.sign(payload, 'secret', { expiresIn: '1h' });
}

// VULNERABILITY: No expiration in JWT
function signTokenNoExpiry(payload) {
    // BAD: Token never expires
    return jwt.sign(payload, JWT_SECRET);
}

// VULNERABILITY: Storing sensitive data in JWT payload
function createUserToken(user) {
    // BAD: Password hash in token (visible in base64)
    return jwt.sign({
        id: user.id,
        email: user.email,
        password_hash: user.password_hash,  // NEVER do this
        credit_card: user.credit_card       // NEVER do this
    }, JWT_SECRET);
}

// VULNERABILITY: Weak password hashing
function hashPassword(password) {
    // BAD: MD5 is cryptographically broken
    return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABILITY: Using SHA1 for security
function generateApiKey(userId) {
    // BAD: SHA1 is deprecated for security purposes
    return crypto.createHash('sha1').update(userId + Date.now()).digest('hex');
}

// VULNERABILITY: Predictable random for tokens
function generateResetToken() {
    // BAD: Math.random is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

// VULNERABILITY: ECB mode encryption
function encryptData(data, key) {
    // BAD: ECB mode reveals patterns
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// VULNERABILITY: Hardcoded IV
function encryptWithHardcodedIV(data, key) {
    // BAD: IV should be random
    const iv = Buffer.from('0000000000000000');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// VULNERABILITY: Timing attack in comparison
function verifyApiKey(provided, stored) {
    // BAD: Early return reveals information via timing
    if (provided.length !== stored.length) {
        return false;
    }
    for (let i = 0; i < provided.length; i++) {
        if (provided[i] !== stored[i]) {
            return false;
        }
    }
    return true;
}

// SECURE EXAMPLE: Proper JWT verification
function verifyTokenSecure(token) {
    // GOOD: Explicitly specify allowed algorithms
    return jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256'],
        maxAge: '1h'
    });
}

// SECURE EXAMPLE: Constant-time comparison
function verifyApiKeySecure(provided, stored) {
    // GOOD: crypto.timingSafeEqual prevents timing attacks
    const a = Buffer.from(provided);
    const b = Buffer.from(stored);
    if (a.length !== b.length) {
        return false;
    }
    return crypto.timingSafeEqual(a, b);
}

// SECURE EXAMPLE: Strong password hashing
async function hashPasswordSecure(password) {
    // GOOD: Use bcrypt or argon2
    const bcrypt = require('bcrypt');
    return await bcrypt.hash(password, 12);
}

module.exports = {
    JWT_SECRET,
    API_KEYS,
    verifyTokenInsecure,
    signTokenWeakSecret,
    hashPassword,
    generateResetToken
};
