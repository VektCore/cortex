package com.example.vulnerable;

import java.sql.*;
import java.io.*;
import javax.servlet.http.*;

/**
 * Controller with SQL Injection and other vulnerabilities.
 * CWE-89: SQL Injection
 * CWE-22: Path Traversal
 * Severity: CRITICAL
 */
public class UserController {

    private Connection connection;

    // VULNERABILITY: SQL Injection via string concatenation
    public User getUserById(String userId) throws SQLException {
        // BAD: Direct string concatenation
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        if (rs.next()) {
            return new User(rs.getString("id"), rs.getString("name"));
        }
        return null;
    }

    // VULNERABILITY: SQL Injection via String.format
    public boolean authenticateUser(String username, String password) throws SQLException {
        // BAD: String.format in SQL query
        String query = String.format(
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'",
            username, password
        );

        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }

    // VULNERABILITY: SQL Injection in ORDER BY
    public ResultSet getUsersSorted(String sortColumn) throws SQLException {
        // BAD: Unsanitized column name
        String query = "SELECT * FROM users ORDER BY " + sortColumn;
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(query);
    }

    // VULNERABILITY: SQL Injection in LIKE clause
    public ResultSet searchUsers(String searchTerm) throws SQLException {
        // BAD: LIKE with unsanitized input
        String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(query);
    }

    // VULNERABILITY: SQL Injection in IN clause
    public ResultSet getUsersInDepartments(String[] departments) throws SQLException {
        // BAD: Building IN clause from array
        String deptList = String.join("','", departments);
        String query = "SELECT * FROM users WHERE department IN ('" + deptList + "')";
        Statement stmt = connection.createStatement();
        return stmt.executeQuery(query);
    }

    // VULNERABILITY: Path Traversal in file download
    public void downloadFile(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String filename = request.getParameter("file");

        // BAD: No path validation
        File file = new File("/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);

        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        fis.close();
    }

    // VULNERABILITY: Command Injection
    public String runDiagnostics(String host) throws IOException {
        // BAD: Shell command with user input
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("ping -c 1 " + host);

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );

        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // VULNERABILITY: Unsafe deserialization
    public Object loadUserData(byte[] serializedData)
            throws IOException, ClassNotFoundException {
        // BAD: Deserializing untrusted data
        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(serializedData)
        );
        return ois.readObject();
    }

    // SECURE EXAMPLE: Parameterized query
    public User getUserByIdSecure(String userId) throws SQLException {
        // GOOD: Parameterized query
        String query = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = connection.prepareStatement(query);
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();

        if (rs.next()) {
            return new User(rs.getString("id"), rs.getString("name"));
        }
        return null;
    }

    // SECURE EXAMPLE: Path validation
    public void downloadFileSecure(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String filename = request.getParameter("file");

        // GOOD: Validate path
        File baseDir = new File("/uploads/").getCanonicalFile();
        File requestedFile = new File(baseDir, filename).getCanonicalFile();

        if (!requestedFile.getPath().startsWith(baseDir.getPath())) {
            throw new SecurityException("Path traversal attempt detected");
        }

        FileInputStream fis = new FileInputStream(requestedFile);
        // ... rest of implementation
    }

    // Simple User class for completeness
    public static class User {
        public String id;
        public String name;

        public User(String id, String name) {
            this.id = id;
            this.name = name;
        }
    }
}
