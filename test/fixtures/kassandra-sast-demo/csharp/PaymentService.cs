// Intentionally vulnerable: hardcoded credentials, weak crypto, SSRF.
// CWE-798, CWE-327, CWE-330, CWE-918.
using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KassandraSastDemo
{
    public class PaymentService
    {
        // VULNERABILITY: Hardcoded credentials
        private const string StripeSecretKey = "sk_live_51ABC123xyz789secretkey";
        private const string DbPassword = "ProductionPassword123!";
        private const string EncryptionKey = "0123456789abcdef";

        // VULNERABILITY: Weak crypto (MD5)
        public string HashPassword(string password)
        {
            using var md5 = MD5.Create(); // BAD: MD5 is broken
            var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
            return BitConverter.ToString(hash).Replace("-", "");
        }

        // VULNERABILITY: Insecure random for security purposes
        public string GenerateTransactionId()
        {
            // BAD: System.Random is not cryptographically secure
            var rng = new Random();
            return rng.Next().ToString("X");
        }

        // VULNERABILITY: DES encryption (weak)
        public byte[] EncryptData(string data)
        {
            using var des = DES.Create(); // BAD: DES is deprecated
            des.Key = Encoding.UTF8.GetBytes(EncryptionKey.Substring(0, 8));
            des.Mode = CipherMode.ECB; // BAD: ECB mode leaks patterns
            using var enc = des.CreateEncryptor();
            var bytes = Encoding.UTF8.GetBytes(data);
            return enc.TransformFinalBlock(bytes, 0, bytes.Length);
        }

        // VULNERABILITY: SSRF
        public async Task<string> FetchExternalData(string userProvidedUrl)
        {
            using var client = new HttpClient();
            // BAD: no URL validation, attacker can hit internal endpoints
            return await client.GetStringAsync(userProvidedUrl);
        }

        // VULNERABILITY: Disabling certificate validation
        public HttpClient CreateInsecureClient()
        {
            var handler = new HttpClientHandler
            {
                // BAD: accepts any certificate, MITM possible
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true
            };
            return new HttpClient(handler);
        }
    }
}
