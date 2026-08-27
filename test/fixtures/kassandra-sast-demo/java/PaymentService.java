package com.example.vulnerable;

import java.sql.*;
import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import javax.xml.parsers.*;
import org.xml.sax.*;

/**
 * Payment Service with Multiple Vulnerabilities
 * Added for SAST workflow validation
 */
public class PaymentService {

    // VULNERABILITY: Hardcoded credentials
    // CWE-798: Use of Hard-coded Credentials
    private static final String DB_PASSWORD = "ProductionPassword123!";
    private static final String API_KEY = "sk-live-payment-api-key-secret";
    private static final String ENCRYPTION_KEY = "0123456789abcdef";

    // VULNERABILITY: SQL Injection
    // CWE-89: SQL Injection
    public ResultSet getPaymentHistory(String customerId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/payments", "root", DB_PASSWORD);
        Statement stmt = conn.createStatement();
        // BAD: String concatenation in SQL query
        String query = "SELECT * FROM payments WHERE customer_id = '" + customerId + "'";
        return stmt.executeQuery(query);
    }

    // VULNERABILITY: Weak encryption algorithm
    // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    public byte[] encryptData(String data) throws Exception {
        // BAD: DES is deprecated and weak
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKey key = SecretKeyFactory.getInstance("DES")
            .generateSecret(new DESKeySpec(ENCRYPTION_KEY.getBytes()));
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes());
    }

    // VULNERABILITY: Insecure random number generation
    // CWE-330: Use of Insufficiently Random Values
    public String generateTransactionId() {
        // BAD: java.util.Random is not cryptographically secure
        java.util.Random random = new java.util.Random();
        return String.valueOf(random.nextLong());
    }

    // VULNERABILITY: SSRF
    // CWE-918: Server-Side Request Forgery
    public String fetchExternalData(String userProvidedUrl) throws Exception {
        // BAD: No URL validation
        URL url = new URL(userProvidedUrl);
        BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }
        return result.toString();
    }

    // VULNERABILITY: Path Traversal
    // CWE-22: Path Traversal
    public String readReceipt(String filename) throws IOException {
        // BAD: No path validation
        File file = new File("/var/receipts/" + filename);
        return new String(java.nio.file.Files.readAllBytes(file.toPath()));
    }

    // VULNERABILITY: XXE
    // CWE-611: XML External Entity
    public void parsePaymentXml(String xmlData) throws Exception {
        // BAD: Default XML parser allows XXE
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new InputSource(new StringReader(xmlData)));
    }

    // VULNERABILITY: Trust all certificates
    // CWE-295: Improper Certificate Validation
    public void sendPaymentNotification(String endpoint) throws Exception {
        // BAD: Trusting all certificates
        javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[] {
            new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
            }
        };

        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }
}
