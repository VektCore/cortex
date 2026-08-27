// Intentionally vulnerable: hardcoded secrets.
// CWE-798: Use of Hard-coded Credentials.
namespace KassandraSastDemo
{
    public static class Config
    {
        // VULNERABILITY: hardcoded API key
        public const string ApiKey = "sk-live-abc123xyz789secretkey";

        // VULNERABILITY: hardcoded database password
        public const string DbPassword = "SuperSecretPassword123!";

        // VULNERABILITY: hardcoded JWT secret
        public const string JwtSecret = "my-super-secret-jwt-key-do-not-share";

        // VULNERABILITY: hardcoded AWS credentials
        public const string AwsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
        public const string AwsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

        // VULNERABILITY: hardcoded service tokens
        public const string StripeSecretKey = "sk_live_51ABC123xyz";
        public const string GitHubToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    }
}
