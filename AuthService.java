package com.example.project2metrics;

import java.sql.*;
import java.security.MessageDigest;

public class AuthService {
    public static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            return bytesToHex(hashedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Hashing failed", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static User authenticate(String username, String password) {
        String hashedPassword = hashPassword(password);
        String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
        
        try (Connection conn = DriverManager.getConnection(DatabaseInitializer.DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setString(1, username);
            stmt.setString(2, hashedPassword);
            
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                return new User(
                    rs.getInt("id"),
                    rs.getString("username"),
                    rs.getString("role"),
                    rs.getString("email"),
                    rs.getString("phone")
                );
            }
            return null;
        } catch (SQLException e) {
            System.err.println("Authentication error: " + e.getMessage());
            return null;
        }
    }

    public static class User {
        private final int id;
        private final String username;
        private final String role;
        private final String email;
        private final String phone;
        
        public User(int id, String username, String role, String email, String phone) {
            this.id = id;
            this.username = username;
            this.role = role;
            this.email = email;
            this.phone = phone;
        }
        
        public int getId() { return id; }
        public String getUsername() { return username; }
        public String getRole() { return role; }
        public String getEmail() { return email; }
        public String getPhone() { return phone; }
    }
}
