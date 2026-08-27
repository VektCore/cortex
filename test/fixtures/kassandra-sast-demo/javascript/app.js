/**
 * Main application with XSS vulnerabilities.
 * CWE-79: Cross-site Scripting (XSS)
 * Severity: HIGH
 */

// VULNERABILITY: DOM XSS via innerHTML
function displayUserMessage(message) {
    // BAD: Direct HTML injection
    document.getElementById('output').innerHTML = message;
}

// VULNERABILITY: DOM XSS via document.write
function writeContent(content) {
    // BAD: document.write with user input
    document.write('<div>' + content + '</div>');
}

// VULNERABILITY: DOM XSS via location hash
function loadFromHash() {
    // BAD: Using hash directly without sanitization
    const content = window.location.hash.substring(1);
    document.getElementById('content').innerHTML = decodeURIComponent(content);
}

// VULNERABILITY: DOM XSS via URL parameter
function displaySearchResults() {
    const params = new URLSearchParams(window.location.search);
    const query = params.get('q');

    // BAD: Inserting URL parameter directly
    document.getElementById('results').innerHTML =
        '<h2>Results for: ' + query + '</h2>';
}

// VULNERABILITY: jQuery html() with user input
function updateProfile(userData) {
    // BAD: jQuery html() with untrusted data
    $('#profile').html('<p>Welcome, ' + userData.name + '</p>');
}

// VULNERABILITY: Template literal XSS
function renderComment(comment) {
    const template = `
        <div class="comment">
            <strong>${comment.author}</strong>
            <p>${comment.text}</p>
        </div>
    `;
    // BAD: innerHTML with template literal
    document.getElementById('comments').innerHTML += template;
}

// VULNERABILITY: Event handler injection
function setupButton(onClickCode) {
    const button = document.createElement('button');
    // BAD: Setting onclick from user input
    button.setAttribute('onclick', onClickCode);
    document.body.appendChild(button);
}

// VULNERABILITY: href javascript: injection
function createLink(url, text) {
    // BAD: No validation of javascript: URLs
    document.getElementById('links').innerHTML +=
        `<a href="${url}">${text}</a>`;
}

// SECURE EXAMPLE: Using textContent
function displayUserMessageSecure(message) {
    // GOOD: textContent doesn't execute HTML
    document.getElementById('output').textContent = message;
}

// SECURE EXAMPLE: Using DOM APIs
function renderCommentSecure(comment) {
    const div = document.createElement('div');
    div.className = 'comment';

    const author = document.createElement('strong');
    // GOOD: textContent is safe
    author.textContent = comment.author;

    const text = document.createElement('p');
    text.textContent = comment.text;

    div.appendChild(author);
    div.appendChild(text);
    document.getElementById('comments').appendChild(div);
}

module.exports = {
    displayUserMessage,
    writeContent,
    loadFromHash,
    displaySearchResults,
    updateProfile,
    renderComment,
    setupButton,
    createLink
};
