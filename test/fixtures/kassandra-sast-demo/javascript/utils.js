/**
 * Utility module with eval and code injection vulnerabilities.
 * CWE-95: Eval Injection
 * Severity: CRITICAL
 */

const vm = require('vm');
const child_process = require('child_process');

// VULNERABILITY: eval() with user input
function calculate(expression) {
    // BAD: eval with user input
    // Attack: expression = "require('child_process').execSync('id')"
    return eval(expression);
}

// VULNERABILITY: Function constructor (indirect eval)
function dynamicFunction(code) {
    // BAD: Function constructor is like eval
    const fn = new Function('x', 'return ' + code);
    return fn;
}

// VULNERABILITY: setTimeout with string (eval)
function scheduleTask(code, delay) {
    // BAD: setTimeout with string executes eval
    setTimeout(code, delay);
}

// VULNERABILITY: setInterval with string
function repeatTask(code, interval) {
    // BAD: setInterval with string executes eval
    return setInterval(code, interval);
}

// VULNERABILITY: vm.runInThisContext (sandbox escape)
function runInContext(code) {
    // BAD: runInThisContext can access host context
    return vm.runInThisContext(code);
}

// VULNERABILITY: Command injection via exec
function runCommand(userInput) {
    // BAD: Shell command with user input
    // Attack: userInput = "; rm -rf /"
    child_process.exec('ls ' + userInput, (err, stdout) => {
        return stdout;
    });
}

// VULNERABILITY: Command injection via execSync
function getFileInfo(filename) {
    // BAD: Shell command with unsanitized input
    return child_process.execSync('file ' + filename).toString();
}

// VULNERABILITY: spawn with shell option
function searchFiles(pattern) {
    // BAD: spawn with shell=true
    return child_process.spawn('grep', ['-r', pattern, '.'], {
        shell: true
    });
}

// VULNERABILITY: Template injection
function renderTemplate(template, data) {
    // BAD: String replacement-based templating
    // Attack: template = "${require('child_process').execSync('id')}"
    return template.replace(/\$\{(\w+)\}/g, (match, key) => {
        return eval(key) || data[key] || '';
    });
}

// VULNERABILITY: JSON.parse with reviver
function parseWithReviver(jsonStr) {
    // BAD: Reviver function can execute code
    return JSON.parse(jsonStr, (key, value) => {
        if (key === 'code') {
            return eval(value);  // NEVER do this
        }
        return value;
    });
}

// VULNERABILITY: Object property access injection
function getProperty(obj, path) {
    // BAD: Allows accessing dangerous properties
    return path.split('.').reduce((o, k) => o[k], obj);
}

// SECURE EXAMPLE: Using spawn without shell
function runCommandSecure(command, args) {
    // GOOD: No shell, explicit argument list
    return child_process.spawn(command, args, { shell: false });
}

// SECURE EXAMPLE: Safe math evaluation
function calculateSecure(expression) {
    // GOOD: Use a safe math expression parser
    const mathjs = require('mathjs');
    const limitedMath = mathjs.create(mathjs.all);
    limitedMath.import({
        import: function () { throw new Error('Disabled'); },
        createUnit: function () { throw new Error('Disabled'); },
        evaluate: function () { throw new Error('Disabled'); },
        parse: function () { throw new Error('Disabled'); },
        simplify: function () { throw new Error('Disabled'); },
        derivative: function () { throw new Error('Disabled'); }
    }, { override: true });

    return limitedMath.evaluate(expression);
}

// SECURE EXAMPLE: Safe template rendering
function renderTemplateSafe(template, data) {
    // GOOD: Only replace known keys, no eval
    return template.replace(/\$\{(\w+)\}/g, (match, key) => {
        return Object.prototype.hasOwnProperty.call(data, key)
            ? String(data[key])
            : '';
    });
}

module.exports = {
    calculate,
    dynamicFunction,
    scheduleTask,
    runCommand,
    getFileInfo,
    renderTemplate
};
