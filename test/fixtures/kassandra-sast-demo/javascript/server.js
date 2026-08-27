/**
 * Server module with Prototype Pollution vulnerabilities.
 * CWE-1321: Prototype Pollution
 * Severity: HIGH
 */

const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

// VULNERABILITY: Prototype Pollution via Object.assign
function mergeConfig(target, source) {
    // BAD: Merging untrusted objects
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            mergeConfig(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// VULNERABILITY: Prototype Pollution via lodash merge
app.post('/api/settings', (req, res) => {
    const settings = {};
    // BAD: lodash merge with user input
    // Attack: {"__proto__": {"admin": true}}
    _.merge(settings, req.body);
    res.json(settings);
});

// VULNERABILITY: Prototype Pollution via spread operator abuse
function updateUser(user, updates) {
    // BAD: Spread operator doesn't protect against __proto__
    const updated = { ...user };
    for (const key of Object.keys(updates)) {
        updated[key] = updates[key];
    }
    return updated;
}

// VULNERABILITY: Object injection via bracket notation
function setProperty(obj, path, value) {
    // BAD: Allows setting __proto__ or constructor
    const parts = path.split('.');
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!current[parts[i]]) {
            current[parts[i]] = {};
        }
        current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = value;
}

// VULNERABILITY: Prototype Pollution via JSON.parse
app.post('/api/import', (req, res) => {
    try {
        // BAD: No sanitization after parsing
        const data = JSON.parse(req.body.json);
        Object.assign(global.config, data);
        res.json({ success: true });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// VULNERABILITY: Unsafe object property access
function getNestedValue(obj, path) {
    // BAD: Allows accessing prototype chain
    return path.split('.').reduce((o, key) => o && o[key], obj);
}

// VULNERABILITY: Constructor pollution
function cloneWithConstructor(obj) {
    // BAD: Allows constructor pollution
    const clone = {};
    for (const key in obj) {
        clone[key] = obj[key];
    }
    return clone;
}

// SECURE EXAMPLE: Using Object.create(null)
function mergeConfigSecure(target, source) {
    const result = Object.create(null);

    for (const key of Object.keys(target)) {
        result[key] = target[key];
    }

    for (const key of Object.keys(source)) {
        // GOOD: Skip dangerous keys
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
        }
        result[key] = source[key];
    }

    return result;
}

// SECURE EXAMPLE: Validate object keys
function setPropertySecure(obj, path, value) {
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    const parts = path.split('.');

    // GOOD: Check for dangerous keys
    if (parts.some(p => dangerousKeys.includes(p))) {
        throw new Error('Invalid property path');
    }

    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!current[parts[i]]) {
            current[parts[i]] = {};
        }
        current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = value;
}

module.exports = { app, mergeConfig, updateUser, setProperty };
