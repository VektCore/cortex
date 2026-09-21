/**
 * Fixture for rules/javascript-ssrf.yaml (cortex-javascript-ssrf).
 *
 * Annotated with Semgrep's native test convention: a comment naming the rule
 * marks the line below it as an expected match, and the negated form marks a
 * line that must stay silent. See the annotations throughout this file.
 *
 * Run:  semgrep --test --config rules test/rules
 *
 * This half covers the TRUE POSITIVES: server-side code where the receiver
 * really does resolve to an HTTP client module.
 */

const axios = require('axios');
const http = require('http');
const https = require('https');
const request = require('request');
const got = require('got');

// --- axios, plain --------------------------------------------------------

async function fetchExternalData(url) {
    // ruleid: cortex-javascript-ssrf
    const response = await axios.get(url);
    return response.data;
}

async function sendWebhook(webhookUrl, data) {
    // ruleid: cortex-javascript-ssrf
    await axios.post(webhookUrl, data);
}

async function validateImageUrl(imageUrl) {
    // ruleid: cortex-javascript-ssrf
    const response = await axios.head(imageUrl);
    return response.headers['content-type'];
}

async function fetchWithOptions(url) {
    // ruleid: cortex-javascript-ssrf
    const response = await axios.get(url, { timeout: 5000, maxRedirects: 10 });
    return response.data;
}

// --- node core http / https ---------------------------------------------

function viaNodeHttp(url, callback) {
    // ruleid: cortex-javascript-ssrf
    http.get(url, (res) => { res.on('end', callback); });
}

function viaNodeHttps(url, callback) {
    // ruleid: cortex-javascript-ssrf
    https.get(url, (res) => { res.on('end', callback); });
}

// The module is picked at runtime, so the receiver is a local alias rather
// than the imported name. Must still fire.
function downloadFile(url, callback) {
    const client = url.startsWith('https') ? https : http;
    // ruleid: cortex-javascript-ssrf
    client.get(url, (res) => { res.on('end', callback); });
}

// --- the `request` package ----------------------------------------------

function proxyViaRequest(targetUrl, cb) {
    // ruleid: cortex-javascript-ssrf
    request(targetUrl, cb);
}

// --- got -----------------------------------------------------------------

async function viaGot(url) {
    // ruleid: cortex-javascript-ssrf
    return got.get(url);
}

// --- global fetch --------------------------------------------------------

async function proxyRequest(targetUrl) {
    // ruleid: cortex-javascript-ssrf
    const response = await fetch(targetUrl);
    return response.text();
}

async function loadExternalContent(params) {
    const { source } = params;
    // ruleid: cortex-javascript-ssrf
    const data = await fetch(source);
    return data.json();
}

// --- target passed as an options object ----------------------------------
//
// `focus-metavariable: $URL` narrows the sink to the target argument. These
// guard that narrowing it does not lose the case where the target is nested
// inside a config object, which is how both axios and node http are normally
// called.

async function viaAxiosConfig(userUrl) {
    // ruleid: cortex-javascript-ssrf
    return axios({ url: userUrl, method: 'GET' });
}

async function viaAxiosRequest(userUrl) {
    // ruleid: cortex-javascript-ssrf
    return axios.request({ url: userUrl });
}

function viaHttpsOptions(userHost, cb) {
    // ruleid: cortex-javascript-ssrf
    return https.request({ hostname: userHost, path: '/charge' }, cb);
}

// Mirror of the above with a fixed host: the config object is not tainted, so
// nothing may fire. The pre-existing rule reported this shape.
function fixedHostOptions(cb) {
    // ok: cortex-javascript-ssrf
    return https.request({ hostname: 'api.payment.com', path: '/charge' }, cb);
}

// --- arrow functions ------------------------------------------------------

// ruleid: cortex-javascript-ssrf
const proxyArrow = (target) => axios.get(target);

const proxyArrowBlock = async (_ctx, target) => {
    // ruleid: cortex-javascript-ssrf
    return axios.get(target);
};

// Not a parameter: a module constant referenced from inside an arrow. The
// pre-existing source pattern tainted every identifier inside any arrow
// function, so this used to be reported.
const STATUS_URL = 'https://status.internal/ping';
const ping = () => {
    // ok: cortex-javascript-ssrf
    return axios.get(STATUS_URL);
};

// --- sanitizers ----------------------------------------------------------

// The declared sanitizer: taint dies at `new URL(...).hostname`.
async function probeHost(userUrl) {
    // ok: cortex-javascript-ssrf
    return axios.get(new URL(userUrl).hostname);
}

// KNOWN LIMITATION, deliberately asserted as firing.
//
// The allowlist guard below is a real defence, but the rule cannot see it:
// `$ALLOWLIST.includes(...)` sanitizes only the *result* of the `includes`
// call, and the value actually sent to axios is `parsedUrl.href`, which is
// still tainted. The pre-existing rule reported this line too, so it is not a
// regression from the sink rework. It is asserted here rather than silenced so
// that anyone who fixes the sanitizers sees this test flip — widening the
// sanitizers to swallow it blindly would cost true positives, which in an SSRF
// rule is the more expensive error.
const ALLOWED_DOMAINS = ['api.github.com'];

async function fetchExternalDataSecure(url) {
    const parsedUrl = new URL(url);
    if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
        throw new Error('Domain not allowed');
    }
    // ruleid: cortex-javascript-ssrf
    return axios.get(parsedUrl.href);
}

// --- constant target: nothing user-controlled reaches the URL ------------

async function heartbeat(payload) {
    // ok: cortex-javascript-ssrf
    await axios.post('https://status.internal/heartbeat', payload);
}

module.exports = {
    fetchExternalData, sendWebhook, validateImageUrl, fetchWithOptions,
    viaNodeHttp, viaNodeHttps, downloadFile, proxyViaRequest, viaGot,
    proxyRequest, loadExternalContent, fetchExternalDataSecure, heartbeat,
};
