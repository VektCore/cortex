/**
 * API module with SSRF vulnerabilities.
 * CWE-918: Server-Side Request Forgery (SSRF)
 * Severity: HIGH
 */

const axios = require('axios');
const fetch = require('node-fetch');
const http = require('http');
const https = require('https');

// VULNERABILITY: SSRF via axios
async function fetchExternalData(url) {
    // BAD: No URL validation
    // Attack: url = "http://169.254.169.254/latest/meta-data/"
    const response = await axios.get(url);
    return response.data;
}

// VULNERABILITY: SSRF via fetch
async function proxyRequest(targetUrl) {
    // BAD: Direct URL passthrough
    // Attack: targetUrl = "http://localhost:3000/admin"
    const response = await fetch(targetUrl);
    return await response.text();
}

// VULNERABILITY: SSRF via http.get
function downloadFile(url, callback) {
    // BAD: No URL validation
    const client = url.startsWith('https') ? https : http;
    client.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => callback(null, data));
    }).on('error', callback);
}

// VULNERABILITY: SSRF via image URL
async function validateImageUrl(imageUrl) {
    // BAD: Fetching arbitrary URLs to "validate" images
    // Attack: imageUrl = "file:///etc/passwd"
    try {
        const response = await axios.head(imageUrl);
        return response.headers['content-type']?.startsWith('image/');
    } catch {
        return false;
    }
}

// VULNERABILITY: SSRF via webhook
async function sendWebhook(webhookUrl, data) {
    // BAD: User-controlled webhook URL
    // Attack: webhookUrl = "http://internal-service.local/admin"
    await axios.post(webhookUrl, data);
}

// VULNERABILITY: SSRF via DNS rebinding
async function fetchWithTimeout(url) {
    // BAD: DNS rebinding attacks possible
    // First request resolves to safe IP, subsequent to internal IP
    const response = await axios.get(url, { timeout: 5000 });
    return response.data;
}

// VULNERABILITY: SSRF via redirect following
async function fetchFollowRedirects(url) {
    // BAD: Following redirects to internal URLs
    // Attack: url redirects to http://127.0.0.1:8080
    const response = await axios.get(url, { maxRedirects: 10 });
    return response.data;
}

// VULNERABILITY: SSRF via URL parameter
async function loadExternalContent(params) {
    const { source, format } = params;
    // BAD: URL from user parameters
    const data = await fetch(source);
    return format === 'json' ? await data.json() : await data.text();
}

// SECURE EXAMPLE: URL allowlist
const ALLOWED_DOMAINS = ['api.github.com', 'api.twitter.com'];

async function fetchExternalDataSecure(url) {
    const parsedUrl = new URL(url);

    // GOOD: Validate against allowlist
    if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
        throw new Error('Domain not allowed');
    }

    // GOOD: Ensure HTTPS
    if (parsedUrl.protocol !== 'https:') {
        throw new Error('HTTPS required');
    }

    // GOOD: Block private IPs
    const ip = await dns.resolve(parsedUrl.hostname);
    if (isPrivateIP(ip)) {
        throw new Error('Private IPs not allowed');
    }

    return await axios.get(url);
}

// SECURE EXAMPLE: Block internal networks
function isPrivateIP(ip) {
    // GOOD: Check for private IP ranges
    const privateRanges = [
        /^127\./,
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /^169\.254\./,
        /^0\./,
        /^localhost$/i
    ];
    return privateRanges.some(range => range.test(ip));
}

module.exports = {
    fetchExternalData,
    proxyRequest,
    downloadFile,
    validateImageUrl,
    sendWebhook
};
