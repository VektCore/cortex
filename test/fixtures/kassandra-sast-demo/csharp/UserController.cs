// Intentionally vulnerable code for SAST validation.
// CWE-89: SQL Injection, CWE-22: Path Traversal, CWE-78: Command Injection.
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;

namespace KassandraSastDemo
{
    public class UserController
    {
        private readonly string _connectionString;

        public UserController(string connectionString)
        {
            _connectionString = connectionString;
        }

        // VULNERABILITY: SQL Injection via string concatenation
        public string GetUserById(string userId)
        {
            using var conn = new SqlConnection(_connectionString);
            conn.Open();
            // BAD: direct concatenation
            var query = "SELECT * FROM users WHERE id = " + userId;
            using var cmd = new SqlCommand(query, conn);
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? reader["name"].ToString() : null;
        }

        // VULNERABILITY: SQL Injection via string interpolation
        public bool AuthenticateUser(string username, string password)
        {
            using var conn = new SqlConnection(_connectionString);
            conn.Open();
            // BAD: interpolation in SQL
            var query = $"SELECT * FROM users WHERE username='{username}' AND password='{password}'";
            using var cmd = new SqlCommand(query, conn);
            return cmd.ExecuteScalar() != null;
        }

        // VULNERABILITY: Path Traversal
        public string ReadUploadedFile(string filename)
        {
            // BAD: no validation, attacker can traverse with "../"
            var path = Path.Combine("/var/www/uploads", filename);
            return File.ReadAllText(path);
        }

        // VULNERABILITY: Command Injection
        public string PingHost(string host)
        {
            // BAD: user input concatenated into a shell command
            var psi = new ProcessStartInfo("cmd.exe", "/c ping -n 1 " + host)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi);
            return proc.StandardOutput.ReadToEnd();
        }

        // SECURE EXAMPLE: parameterized query
        public string GetUserByIdSecure(int userId)
        {
            using var conn = new SqlConnection(_connectionString);
            conn.Open();
            using var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", userId);
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? reader["name"].ToString() : null;
        }
    }
}
