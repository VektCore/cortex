"""
Configuration module with Hardcoded Secrets.
CWE-798: Use of Hard-coded Credentials
Severity: HIGH
"""

import os

# VULNERABILITY: Hardcoded API key
API_KEY = "sk-live-abc123xyz789secretkey"

# VULNERABILITY: Hardcoded database password
DATABASE_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "database": "production_db",
    "user": "admin",
    "password": "SuperSecretPassword123!"  # BAD: Hardcoded password
}

# VULNERABILITY: Hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABILITY: Hardcoded JWT secret
JWT_SECRET = "my-super-secret-jwt-key-do-not-share"

# VULNERABILITY: Hardcoded encryption key
ENCRYPTION_KEY = b"0123456789abcdef0123456789abcdef"

# VULNERABILITY: Hardcoded OAuth tokens
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
SLACK_WEBHOOK = "https://hooks.slack.example/services/TXXXXXXXX/BXXXXXXXX/xxxxxxxxxxxxxxxxxx"

# VULNERABILITY: Private key embedded in code
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyf8p5WwSVs7SbKZPXFXpPfXqzNjKd
tNyqKLmKr0MeT6O1TwT0ykPNxcJNqHbVnT6pEjX5pI2vrwLMfz/7TsKoGc4NzPw9
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
-----END RSA PRIVATE KEY-----"""

# VULNERABILITY: Hardcoded service credentials
class ServiceCredentials:
    STRIPE_SECRET_KEY = "sk_live_51ABC123xyz"
    SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxx"
    TWILIO_AUTH_TOKEN = "your_auth_token_here"


# SECURE EXAMPLE: Using environment variables
def get_secure_config():
    """Get configuration from environment variables - SECURE."""
    return {
        "api_key": os.environ.get("API_KEY"),
        "db_password": os.environ.get("DB_PASSWORD"),
        "jwt_secret": os.environ.get("JWT_SECRET"),
    }
