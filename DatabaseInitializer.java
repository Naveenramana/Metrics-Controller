package com.example.project2metrics;

import java.sql.*;

public class DatabaseInitializer {
    public static final String DB_URL = "jdbc:sqlite:metrics.db";

    public static void initializeDatabase() {
        try (Connection connection = DriverManager.getConnection(DB_URL);
             Statement statement = connection.createStatement()) {
            
            // Create tables
            statement.execute("CREATE TABLE IF NOT EXISTS users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "username TEXT UNIQUE NOT NULL, " +
                "password TEXT NOT NULL, " +
                "role TEXT NOT NULL CHECK(role IN ('admin','operator')), " +
                "email TEXT, " +
                "phone TEXT)");

            statement.execute("CREATE TABLE IF NOT EXISTS metrics (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "timestamp TEXT NOT NULL, " +
                "cpuUsage REAL NOT NULL, " +
                "memoryUsage REAL NOT NULL, " +
                "diskUsage REAL NOT NULL, " +
                "is_alarm BOOLEAN DEFAULT FALSE, " +
                "acknowledged_by INTEGER REFERENCES users(id), " +
                "acknowledged_at TEXT)");

            statement.execute("CREATE TABLE IF NOT EXISTS alarm_settings (" +
                "id INTEGER PRIMARY KEY, " +
                "retention_days INTEGER DEFAULT 30, " +
                "cpu_threshold REAL DEFAULT 50, " +
                "memory_threshold REAL DEFAULT 50, " +
                "disk_threshold REAL DEFAULT 50)");

            // Insert default users with CORRECT hashed passwords
            statement.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES " +
                "('admin', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', 'admin'), " + // admin123
                "('operator1', 'ec6e1c25258002eb1c67d15c7f45da7945fa4c58778fd7d88faa5e53e3b4698d', 'operator')"); // operator123

            statement.execute("INSERT OR IGNORE INTO alarm_settings (id, retention_days, cpu_threshold, memory_threshold, disk_threshold) " +
                "VALUES (1, 30, 50, 50, 50)");
            
            System.out.println("Database initialized successfully");
        } catch (SQLException e) {
            System.err.println("Database initialization failed: " + e.getMessage());
        }
    }

    public static void migrateToV2() {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            migrateSchema(conn);
            System.out.println("Database migration completed");
        } catch (SQLException e) {
            System.err.println("Migration failed: " + e.getMessage());
        }
    }

    private static void migrateSchema(Connection conn) throws SQLException {
        if (!columnExists(conn, "metrics", "is_alarm")) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("ALTER TABLE metrics ADD COLUMN is_alarm BOOLEAN DEFAULT FALSE");
            }
        }
        
        if (!columnExists(conn, "metrics", "acknowledged_by")) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("ALTER TABLE metrics ADD COLUMN acknowledged_by INTEGER REFERENCES users(id)");
            }
        }
        
        if (!columnExists(conn, "metrics", "acknowledged_at")) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("ALTER TABLE metrics ADD COLUMN acknowledged_at TEXT");
            }
        }
        
        if (!columnExists(conn, "alarm_settings", "cpu_threshold")) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("ALTER TABLE alarm_settings ADD COLUMN cpu_threshold REAL DEFAULT 50");
                stmt.execute("ALTER TABLE alarm_settings ADD COLUMN memory_threshold REAL DEFAULT 50");
                stmt.execute("ALTER TABLE alarm_settings ADD COLUMN disk_threshold REAL DEFAULT 50");
                
                stmt.execute("UPDATE alarm_settings SET " +
                    "cpu_threshold = 50, " +
                    "memory_threshold = 50, " +
                    "disk_threshold = 50 " +
                    "WHERE id = 1");
            }
        }
        
        try (Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM alarm_settings");
            if (rs.next() && rs.getInt(1) == 0) {
                stmt.execute("INSERT INTO alarm_settings (id, retention_days, cpu_threshold, memory_threshold, disk_threshold) " +
                    "VALUES (1, 30, 50, 50, 50)");
            }
        }
    }

    private static boolean columnExists(Connection conn, String table, String column) {
        try {
            DatabaseMetaData meta = conn.getMetaData();
            ResultSet rs = meta.getColumns(null, null, table, column);
            return rs.next();
        } catch (SQLException e) {
            return false;
        }
    }
}
