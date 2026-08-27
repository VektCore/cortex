# Kassandra SAST Demo - Vulnerable Application

This repository contains intentionally vulnerable code for testing Kassandra's SAST module.

**WARNING**: This code contains security vulnerabilities for educational purposes only. DO NOT use in production.

---

## Quick Start

### 1. Create SAST Project in Kassandra

Go to https://kassandra.red/sast and create a new project:

```
Name: SAST Demo App
Repository URL: https://github.com/YOUR_USER/kassandra-sast-demo
Default Branch: main
Scanner Mode: EXTERNAL (for webhook testing)
Industry: FinTech
Sensitive Data: PII, Financial
Regulations: SOC2, PCI-DSS
```

### 2. Get Your Project ID

After creating the project, copy the Project ID from the URL:
```
https://kassandra.red/sast/projects/{PROJECT_ID}
```

### 3. Run Scanner & Submit Results

See detailed instructions for each scanner below.

---

## Test Scenarios

| Scenario | Description | Scanner | Mode |
|----------|-------------|---------|------|
| A | External webhook with Semgrep | Semgrep | EXTERNAL |
| B | External webhook with Bandit | Bandit | EXTERNAL |
| C | External webhook with ESLint | ESLint | EXTERNAL |
| D | Multiple scanners combined | All | HYBRID |

---

## Scenario A: Semgrep (Python/JS)

### Prerequisites
```bash
# Install Semgrep
pip install semgrep
# or
brew install semgrep
```

### Run Scan
```bash
# Clone this repo
git clone https://github.com/YOUR_USER/kassandra-sast-demo
cd kassandra-sast-demo

# Run Semgrep and output SARIF
semgrep scan --config auto --sarif --output results.sarif .

# Submit to Kassandra
curl -X POST \
  -H "Content-Type: application/json" \
  -H "x-tool-name: semgrep" \
  -d @results.sarif \
  "https://api.kassandra.red/api/v1/sast/webhooks/YOUR_PROJECT_ID/sarif?branch=main"
```

### Expected Findings
- SQL Injection in `python/database.py`
- Command Injection in `python/utils.py`
- Hardcoded Secrets in `python/config.py`
- XSS vulnerabilities in `javascript/app.js`

---

## Scenario B: Bandit (Python only)

### Prerequisites
```bash
pip install bandit
```

### Run Scan
```bash
# Run Bandit with SARIF output
bandit -r python/ -f sarif -o bandit-results.sarif

# Submit to Kassandra
curl -X POST \
  -H "Content-Type: application/json" \
  -H "x-tool-name: bandit" \
  -d @bandit-results.sarif \
  "https://api.kassandra.red/api/v1/sast/webhooks/YOUR_PROJECT_ID/sarif?branch=main"
```

### Expected Findings
- B608: SQL Injection
- B602: Subprocess shell=True
- B105: Hardcoded password
- B301: Pickle usage
- B506: Unsafe YAML load

---

## Scenario C: ESLint Security (JavaScript)

### Prerequisites
```bash
npm install -g eslint @microsoft/eslint-formatter-sarif eslint-plugin-security
```

### Run Scan
```bash
cd javascript/

# Create ESLint config
cat > .eslintrc.json << 'EOF'
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"],
  "parserOptions": {
    "ecmaVersion": 2020
  }
}
EOF

# Run ESLint with SARIF output
eslint . --format @microsoft/eslint-formatter-sarif -o eslint-results.sarif

# Submit to Kassandra
curl -X POST \
  -H "Content-Type: application/json" \
  -H "x-tool-name: eslint-security" \
  -d @eslint-results.sarif \
  "https://api.kassandra.red/api/v1/sast/webhooks/YOUR_PROJECT_ID/sarif?branch=main"
```

### Expected Findings
- security/detect-eval-with-expression
- security/detect-non-literal-fs-filename
- security/detect-object-injection
- security/detect-possible-timing-attacks

---

## Scenario D: GitHub Actions CI/CD

Create `.github/workflows/sast.yml`:

```yaml
name: SAST Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  KASSANDRA_PROJECT_ID: YOUR_PROJECT_ID

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Semgrep scan
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: auto
          generateSarif: true

      - name: Upload Semgrep to Kassandra
        run: |
          curl -X POST \
            -H "Content-Type: application/json" \
            -H "x-tool-name: semgrep" \
            -d @semgrep.sarif \
            "https://api.kassandra.red/api/v1/sast/webhooks/$KASSANDRA_PROJECT_ID/sarif?branch=${{ github.ref_name }}&commit=${{ github.sha }}"

      # Bandit scan (Python)
      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r python/ -f sarif -o bandit.sarif || true

      - name: Upload Bandit to Kassandra
        run: |
          curl -X POST \
            -H "Content-Type: application/json" \
            -H "x-tool-name: bandit" \
            -d @bandit.sarif \
            "https://api.kassandra.red/api/v1/sast/webhooks/$KASSANDRA_PROJECT_ID/sarif?branch=${{ github.ref_name }}"
```

---

## Vulnerabilities Included

### Python (`python/`)

| File | Vulnerability | CWE | Severity |
|------|---------------|-----|----------|
| database.py | SQL Injection | CWE-89 | CRITICAL |
| utils.py | Command Injection | CWE-78 | CRITICAL |
| config.py | Hardcoded Secrets | CWE-798 | HIGH |
| auth.py | Weak Crypto (MD5) | CWE-328 | MEDIUM |
| serializer.py | Insecure Deserialization | CWE-502 | HIGH |
| file_handler.py | Path Traversal | CWE-22 | HIGH |

### JavaScript (`javascript/`)

| File | Vulnerability | CWE | Severity |
|------|---------------|-----|----------|
| app.js | XSS (DOM) | CWE-79 | HIGH |
| server.js | Prototype Pollution | CWE-1321 | HIGH |
| api.js | SSRF | CWE-918 | HIGH |
| auth.js | JWT Secret Exposure | CWE-798 | CRITICAL |
| utils.js | eval() usage | CWE-95 | CRITICAL |

### Java (`java/`)

| File | Vulnerability | CWE | Severity |
|------|---------------|-----|----------|
| UserController.java | SQL Injection | CWE-89 | CRITICAL |
| FileService.java | Path Traversal | CWE-22 | HIGH |
| XmlParser.java | XXE Injection | CWE-611 | HIGH |

---

## Kassandra SAST Features to Test

### 1. Deduplication
Run the same scan twice - Kassandra should deduplicate identical findings.

### 2. LLM Enrichment
Check findings detail page for:
- Adjusted severity (may differ from scanner)
- Developer explanation
- Business impact assessment
- Suggested fix with code

### 3. False Positive Detection
Some findings may be marked as false positives by LLM analysis.

### 4. Exposure Creation
HIGH/CRITICAL findings should auto-create Exposures in the main vulnerability system.

### 5. SLA Tracking
Configure SLAs in project settings and verify deadline calculations.

### 6. Pipeline Pass/Fail
Configure `fail_on: ["critical"]` and verify webhook response indicates failure.

---

## Sync vs Async Processing

### Async (Production - Default)
```bash
# Returns immediately, processes in background
curl -X POST -d @results.sarif \
  "https://api.kassandra.red/api/v1/sast/webhooks/PROJECT_ID/sarif"

# Response:
# {"scan_id": "uuid", "status": "queued", "message": "Scan queued for processing"}
```

### Sync (Testing)
```bash
# Waits for processing, returns results immediately
curl -X POST -d @results.sarif \
  "https://api.kassandra.red/api/v1/sast/webhooks/PROJECT_ID/sarif?sync=true"

# Response includes full processing results
```

---

## Troubleshooting

### No findings appearing?
1. Check SARIF format is valid: `cat results.sarif | jq .`
2. Verify project ID is correct
3. Check Kassandra logs: `docker logs kassandra-core`

### LLM enrichment not working?
- Requires `ANTHROPIC_API_KEY` configured on server
- Only enriches HIGH/CRITICAL findings by default

### Pipeline always passing?
- Configure `fail_on` in project settings
- Default only fails on CRITICAL

---

## License

MIT - For educational purposes only. Contains intentionally vulnerable code.
