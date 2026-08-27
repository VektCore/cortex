/**
 * Payment Processing Module with Vulnerabilities
 * Added for SAST workflow validation
 */

const crypto = require('crypto');
const https = require('https');

// VULNERABILITY: Hardcoded API keys
// CWE-798: Use of Hard-coded Credentials
const STRIPE_SECRET_KEY = 'sk_live_51ABC123xyz789secretkey';
const PAYMENT_API_KEY = 'pk_live_payment_key_do_not_share';

// VULNERABILITY: Weak cryptographic algorithm
// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
function hashPassword(password) {
    // BAD: MD5 is cryptographically broken
    return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABILITY: Insecure TLS configuration
// CWE-295: Improper Certificate Validation
function makePaymentRequest(data) {
    const options = {
        hostname: 'api.payment.com',
        port: 443,
        path: '/charge',
        method: 'POST',
        rejectUnauthorized: false  // BAD: Disables SSL verification
    };

    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            resolve(res);
        });
        req.write(JSON.stringify(data));
        req.end();
    });
}

// VULNERABILITY: SQL Injection
// CWE-89: SQL Injection
function getTransactionHistory(userId) {
    const db = require('./db');
    // BAD: String concatenation in SQL
    const query = "SELECT * FROM transactions WHERE user_id = '" + userId + "'";
    return db.query(query);
}

// VULNERABILITY: Regex DoS (ReDoS)
// CWE-1333: Inefficient Regular Expression Complexity
function validateEmail(email) {
    // BAD: Catastrophic backtracking possible
    const regex = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z0-9]+)+$/;
    return regex.test(email);
}

// VULNERABILITY: Prototype Pollution
// CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
function mergeConfig(target, source) {
    for (let key in source) {
        // BAD: No __proto__ check
        target[key] = source[key];
    }
    return target;
}

// VULNERABILITY: Eval with user input
// CWE-95: Eval Injection
function calculateDiscount(expression) {
    // BAD: eval with potentially user-controlled input
    return eval(expression);
}

// VULNERABILITY: Information exposure in error messages
// CWE-209: Information Exposure Through an Error Message
function processPayment(cardNumber, amount) {
    try {
        // Payment logic here
        throw new Error(`Payment failed for card ${cardNumber} with amount ${amount}`);
    } catch (error) {
        // BAD: Exposes sensitive data in error
        console.log(error.message);
        throw error;
    }
}

module.exports = {
    hashPassword,
    makePaymentRequest,
    getTransactionHistory,
    validateEmail,
    mergeConfig,
    calculateDiscount,
    processPayment
};
