# Test fixtures

## `kassandra-sast-demo/`

Intentionally vulnerable code, used as the **canonical end-to-end fixture**
for Cortex. The Cortex pipeline is expected to detect the vulnerabilities
listed below; the E2E test suite asserts this contract.

Do **not** treat this code as a production reference. Every file is
deliberately broken.

### Vulnerabilities per language

| Path | Vulnerability | CWE | Severity |
|---|---|---|---|
| `python/database.py` | SQL Injection | CWE-89 | CRITICAL |
| `python/utils.py` | Command Injection | CWE-78 | CRITICAL |
| `python/config.py` | Hardcoded Secrets | CWE-798 | HIGH |
| `python/auth.py` | Weak Crypto | CWE-328 | MEDIUM |
| `python/serializer.py` | Insecure Deserialization | CWE-502 | HIGH |
| `python/file_handler.py` | Path Traversal | CWE-22 | HIGH |
| `python/api_handler.py` | SSRF / XXE / SQLi / etc. | many | HIGH |
| `javascript/app.js` | XSS | CWE-79 | HIGH |
| `javascript/server.js` | Prototype Pollution | CWE-1321 | HIGH |
| `javascript/api.js` | SSRF | CWE-918 | HIGH |
| `javascript/auth.js` | JWT secrets / weak crypto | CWE-798 | CRITICAL |
| `javascript/utils.js` | `eval()` / command injection | CWE-95 | CRITICAL |
| `javascript/payment.js` | Multiple | multiple | HIGH |
| `java/UserController.java` | SQL Injection / path traversal / RCE | CWE-89 | CRITICAL |
| `java/PaymentService.java` | Weak crypto + SSRF + XXE | multiple | HIGH |
| `java/XmlParser.java` | XXE | CWE-611 | HIGH |
| `csharp/UserController.cs` | SQL Injection / path traversal / RCE | CWE-89 | CRITICAL |
| `csharp/PaymentService.cs` | Hardcoded creds + weak crypto + SSRF | multiple | HIGH |
| `csharp/XmlParser.cs` | XXE | CWE-611 | HIGH |
| `csharp/AuthService.cs` | Insecure deserialization | CWE-502 | HIGH |
| `csharp/Config.cs` | Hardcoded secrets | CWE-798 | HIGH |
