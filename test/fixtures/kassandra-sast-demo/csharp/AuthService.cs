// Intentionally vulnerable: insecure deserialization, weak JWT handling.
// CWE-502, CWE-327, CWE-347.
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace KassandraSastDemo
{
    public class AuthService
    {
        // VULNERABILITY: BinaryFormatter — arbitrary code execution on deserialize
        public object LoadSession(byte[] data)
        {
#pragma warning disable SYSLIB0011
            // BAD: BinaryFormatter is unsafe with untrusted data
            var formatter = new BinaryFormatter();
            using var ms = new MemoryStream(data);
            return formatter.Deserialize(ms);
#pragma warning restore SYSLIB0011
        }

        // VULNERABILITY: timing-leaking comparison
        public bool VerifyApiKey(string provided, string stored)
        {
            // BAD: short-circuit comparison leaks length and content via timing
            if (provided.Length != stored.Length) return false;
            for (var i = 0; i < provided.Length; i++)
            {
                if (provided[i] != stored[i]) return false;
            }
            return true;
        }
    }
}
