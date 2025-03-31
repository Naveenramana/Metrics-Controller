package com.example.project2metrics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.BindException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.sql.*;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MetricsApplication {
    public static void main(String[] args) {
        DatabaseInitializer.initializeDatabase();
        DatabaseInitializer.migrateToV2();
        AuthService.initializeDefaultUsers();
        
        MetricsCollector collector = new MetricsCollector();
        Thread metricsCollectorThread = new Thread(collector);
        metricsCollectorThread.setDaemon(true);
        metricsCollectorThread.start();
        
        MetricsHttpServer.start();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\nShutting down gracefully...");
            MetricsHttpServer.stop();
            collector.stop();
        }));
    }
}

class DatabaseInitializer {
    public static final String DB_URL = "jdbc:sqlite:metrics.db";

    public static void initializeDatabase() {
        try (Connection connection = DriverManager.getConnection(DB_URL);
             Statement statement = connection.createStatement()) {
            
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

            statement.execute("INSERT OR IGNORE INTO alarm_settings (id, retention_days, cpu_threshold, memory_threshold, disk_threshold) " +
                "VALUES (1, 30, 50, 50, 50)");
            
            System.out.println("✅ Database initialized successfully");
        } catch (SQLException e) {
            System.err.println("❌ Database initialization failed: " + e.getMessage());
        }
    }

    private static void initializeDefaultData(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES " +
                "('admin', 'admin123', 'admin'), " +
                "('operator1', 'op123', 'operator')");
        }
    }

    public static void migrateToV2() {
        try (Connection conn = DriverManager.getConnection(DB_URL)) {
            migrateSchema(conn);
            System.out.println("✅ Database migration completed");
        } catch (SQLException e) {
            System.err.println("❌ Migration failed: " + e.getMessage());
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

class AuthService {
    public static void initializeDefaultUsers() {
        try (Connection conn = DriverManager.getConnection(DatabaseInitializer.DB_URL);
             Statement stmt = conn.createStatement()) {
            System.out.println("✅ User initialization already handled during database setup");
        } catch (SQLException e) {
            System.err.println("❌ Failed to initialize users: " + e.getMessage());
        }
    }
    
    public static User authenticate(String username, String password) {
        System.out.println("Authenticating user: " + username);
        String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
        
        try (Connection conn = DriverManager.getConnection(DatabaseInitializer.DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setString(1, username);
            stmt.setString(2, password);
            System.out.println("Executing query: " + stmt);
            
            ResultSet rs = stmt.executeQuery();
            
            if (rs.next()) {
                User user = new User(
                    rs.getInt("id"),
                    rs.getString("username"),
                    rs.getString("role"),
                    rs.getString("email"),
                    rs.getString("phone")
                );
                System.out.println("User found: " + user.getUsername());
                return user;
            }
            System.out.println("No user found with these credentials");
            return null;
        } catch (SQLException e) {
            System.err.println("❌ Authentication error: " + e.getMessage());
            e.printStackTrace();
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

class Metrics {
    private int id;
    private String timestamp;
    private double cpuUsage;
    private double memoryUsage;
    private double diskUsage;
    private boolean isAlarm;
    private Integer acknowledgedBy;
    private String acknowledgedAt;
    private String acknowledgedByName;

    public Metrics(String timestamp, double cpuUsage, double memoryUsage, double diskUsage) {
        this.timestamp = timestamp;
        this.cpuUsage = cpuUsage;
        this.memoryUsage = memoryUsage;
        this.diskUsage = diskUsage;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getTimestamp() { return timestamp; }
    public double getCpuUsage() { return cpuUsage; }
    public double getMemoryUsage() { return memoryUsage; }
    public double getDiskUsage() { return diskUsage; }
    public boolean isAlarm() { return isAlarm; }
    public void setAlarm(boolean alarm) { isAlarm = alarm; }
    public Integer getAcknowledgedBy() { return acknowledgedBy; }
    public void setAcknowledgedBy(Integer acknowledgedBy) { this.acknowledgedBy = acknowledgedBy; }
    public String getAcknowledgedAt() { return acknowledgedAt; }
    public void setAcknowledgedAt(String acknowledgedAt) { this.acknowledgedAt = acknowledgedAt; }
    public String getAcknowledgedByName() { return acknowledgedByName; }
    public void setAcknowledgedByName(String acknowledgedByName) { this.acknowledgedByName = acknowledgedByName; }
}

class MetricsRepository {
    private static final String DB_URL = "jdbc:sqlite:metrics.db";

    public void save(Metrics metrics) {
        String sql = "INSERT INTO metrics (timestamp, cpuUsage, memoryUsage, diskUsage, is_alarm) VALUES (?, ?, ?, ?, ?)";

        try (Connection connection = DriverManager.getConnection(DB_URL);
             PreparedStatement statement = connection.prepareStatement(sql)) {

            statement.setString(1, metrics.getTimestamp());
            statement.setDouble(2, metrics.getCpuUsage());
            statement.setDouble(3, metrics.getMemoryUsage());
            statement.setDouble(4, metrics.getDiskUsage());
            statement.setBoolean(5, metrics.isAlarm());
            statement.executeUpdate();

            System.out.println("✅ Metrics saved: " + metrics.getTimestamp());
        } catch (SQLException e) {
            System.err.println("❌ Error saving metrics: " + e.getMessage());
        }
    }

    public List<Metrics> findAll() {
        List<Metrics> metricsList = new ArrayList<>();
        String sql = "SELECT * FROM metrics ORDER BY id DESC LIMIT 10";

        try (Connection connection = DriverManager.getConnection(DB_URL);
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {

            while (resultSet.next()) {
                Metrics metrics = createMetricFromResultSet(resultSet);
                metricsList.add(metrics);
            }
        } catch (SQLException e) {
            System.err.println("❌ Error fetching metrics: " + e.getMessage());
        }
        return metricsList;
    }

    public List<Metrics> findByTimeRange(String startTime, String endTime) {
        List<Metrics> metricsList = new ArrayList<>();
        
        if (startTime == null || startTime.isEmpty() || endTime == null || endTime.isEmpty()) {
            System.out.println("⚠️ Empty time range parameters - returning empty results");
            return metricsList;
        }

        String sql = "SELECT * FROM metrics WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp ASC";

        try (Connection connection = DriverManager.getConnection(DB_URL);
             PreparedStatement statement = connection.prepareStatement(sql)) {

            String formattedStartTime = formatTimestampForSQLite(startTime);
            String formattedEndTime = formatTimestampForSQLite(endTime);

            statement.setString(1, formattedStartTime);
            statement.setString(2, formattedEndTime);
            
            System.out.println("Executing query with time range: " + formattedStartTime + " to " + formattedEndTime);
            
            ResultSet resultSet = statement.executeQuery();

            while (resultSet.next()) {
                Metrics metrics = createMetricFromResultSet(resultSet);
                metricsList.add(metrics);
            }
        } catch (SQLException e) {
            System.err.println("❌ Error fetching metrics by time range: " + e.getMessage());
        }
        return metricsList;
    }

    public List<Metrics> findAlarmsByTimeRange(String startTime, String endTime, Integer userId) {
        List<Metrics> alarms = new ArrayList<>();
        
        if (startTime == null || startTime.isEmpty() || endTime == null || endTime.isEmpty()) {
            System.out.println("⚠️ Empty time range parameters - returning empty alarm results");
            return alarms;
        }

        String sql = "SELECT m.*, u.username as acknowledged_by_name " +
                     "FROM metrics m " +
                     "LEFT JOIN users u ON m.acknowledged_by = u.id " +
                     "WHERE m.is_alarm = TRUE AND m.timestamp BETWEEN ? AND ? " +
                     (userId != null ? "AND (m.acknowledged_by = ? OR m.acknowledged_by IS NULL)" : "") + 
                     " ORDER BY m.timestamp DESC";
        
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setString(1, formatTimestampForSQLite(startTime));
            stmt.setString(2, formatTimestampForSQLite(endTime));
            if (userId != null) stmt.setInt(3, userId);
            
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Metrics metric = createMetricFromResultSet(rs);
                metric.setAcknowledgedByName(rs.getString("acknowledged_by_name"));
                alarms.add(metric);
            }
        } catch (SQLException e) {
            System.err.println("❌ Error fetching alarms: " + e.getMessage());
        }
        return alarms;
    }
    
    public void acknowledgeAlarm(int alarmId, int userId) {
        String sql = "UPDATE metrics SET acknowledged_by = ?, acknowledged_at = datetime('now') WHERE id = ?";
        
        try (Connection conn = DriverManager.getConnection(DB_URL + "?journal_mode=WAL");
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            conn.setAutoCommit(false);
            stmt.setInt(1, userId);
            stmt.setInt(2, alarmId);
            
            int rowsUpdated = stmt.executeUpdate();
            conn.commit();
            
            System.out.println("✅ Acknowledged alarm ID: " + alarmId + " by user ID: " + userId + 
                             " (Rows updated: " + rowsUpdated + ")");
        } catch (SQLException e) {
            System.err.println("❌ Error acknowledging alarm: " + e.getMessage());
        }
    }
    
    public int getRetentionDays() {
        String sql = "SELECT retention_days FROM alarm_settings LIMIT 1";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            return rs.next() ? rs.getInt("retention_days") : 30;
        } catch (SQLException e) {
            System.err.println("❌ Error getting retention days: " + e.getMessage());
            return 30;
        }
    }
    
    public void setRetentionDays(int days) {
        String sql = "UPDATE alarm_settings SET retention_days = ? WHERE id = 1";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setInt(1, days);
            stmt.executeUpdate();
            System.out.println("✅ Updated retention days to: " + days);
        } catch (SQLException e) {
            System.err.println("❌ Error setting retention days: " + e.getMessage());
        }
    }
    
    public Map<String, Double> getThresholdSettings() {
        String sql = "SELECT cpu_threshold, memory_threshold, disk_threshold FROM alarm_settings LIMIT 1";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            if (rs.next()) {
                Map<String, Double> thresholds = new HashMap<>();
                thresholds.put("cpu", rs.getDouble("cpu_threshold"));
                thresholds.put("memory", rs.getDouble("memory_threshold"));
                thresholds.put("disk", rs.getDouble("disk_threshold"));
                return thresholds;
            }
            return Map.of("cpu", 50.0, "memory", 50.0, "disk", 50.0);
        } catch (SQLException e) {
            System.err.println("❌ Error getting threshold settings: " + e.getMessage());
            return Map.of("cpu", 50.0, "memory", 50.0, "disk", 50.0);
        }
    }
    
    public void setThresholdSettings(double cpu, double memory, double disk) {
        String updateSql = "UPDATE alarm_settings SET cpu_threshold = ?, memory_threshold = ?, disk_threshold = ? WHERE id = 1";
        
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(updateSql)) {
            
            stmt.setDouble(1, cpu);
            stmt.setDouble(2, memory);
            stmt.setDouble(3, disk);
            int updated = stmt.executeUpdate();
            
            if (updated == 0) {
                String insertSql = "INSERT INTO alarm_settings (id, cpu_threshold, memory_threshold, disk_threshold, retention_days) " +
                                 "VALUES (1, ?, ?, ?, 30)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
                    insertStmt.setDouble(1, cpu);
                    insertStmt.setDouble(2, memory);
                    insertStmt.setDouble(3, disk);
                    insertStmt.executeUpdate();
                }
            }
            
            System.out.println("✅ Thresholds updated to CPU: " + cpu + "%, Memory: " + memory + "%, Disk: " + disk + "%");
        } catch (SQLException e) {
            System.err.println("❌ Error updating thresholds: " + e.getMessage());
        }
    }
    
    public void cleanupOldAlarms() {
        String sql = "DELETE FROM metrics WHERE is_alarm = TRUE AND " +
                     "acknowledged_at < date('now', '-' || ? || ' days')";
                     
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setInt(1, getRetentionDays());
            int deleted = stmt.executeUpdate();
            System.out.println("✅ Cleaned up " + deleted + " old alarms");
        } catch (SQLException e) {
            System.err.println("❌ Cleanup failed: " + e.getMessage());
        }
    }

    private Metrics createMetricFromResultSet(ResultSet rs) throws SQLException {
        Metrics metrics = new Metrics(
            rs.getString("timestamp"),
            rs.getDouble("cpuUsage"),
            rs.getDouble("memoryUsage"),
            rs.getDouble("diskUsage")
        );
        metrics.setId(rs.getInt("id"));
        metrics.setAlarm(rs.getBoolean("is_alarm"));
        metrics.setAcknowledgedBy(rs.getInt("acknowledged_by"));
        metrics.setAcknowledgedAt(rs.getString("acknowledged_at"));
        return metrics;
    }

    private String formatTimestampForSQLite(String timestamp) {
        if (timestamp == null || timestamp.isEmpty()) {
            System.err.println("❌ Empty or null timestamp");
            return "";
        }

        try {
            if (timestamp.endsWith("Z")) {
                SimpleDateFormat isoFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                isoFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
                java.util.Date date = isoFormat.parse(timestamp);
                
                SimpleDateFormat outputFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                outputFormat.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata"));
                return outputFormat.format(date);
            }
            
            if (timestamp.matches("^[A-Za-z]+ \\d{1,2}, \\d{4} \\d{1,2}:\\d{2}$")) {
                SimpleDateFormat inputFormat = new SimpleDateFormat("MMMM dd, yyyy HH:mm", Locale.ENGLISH);
                java.util.Date date = inputFormat.parse(timestamp);
                
                SimpleDateFormat outputFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                outputFormat.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata"));
                return outputFormat.format(date);
            }
            
            if (timestamp.contains(" at ")) {
                String normalizedTimestamp = timestamp.replace(" at ", " ");
                if (!normalizedTimestamp.contains(",")) {
                    normalizedTimestamp = normalizedTimestamp.replaceFirst("(\\d+) ", "$1, ");
                }
                
                SimpleDateFormat inputFormat = new SimpleDateFormat("MMMM dd, yyyy hh:mm a", Locale.ENGLISH);
                java.util.Date date = inputFormat.parse(normalizedTimestamp);
                
                SimpleDateFormat outputFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                outputFormat.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata"));
                return outputFormat.format(date);
            }
            
            return timestamp;
        } catch (Exception e) {
            System.err.println("❌ Error formatting timestamp: " + timestamp);
            System.err.println("Error details: " + e.getMessage());
            return timestamp;
        }
    }
}

class MetricsCollector implements Runnable {
    private static final MetricsRepository repository = new MetricsRepository();
    private static final Random random = new Random();
    private static final String CSV_FILE_PATH = "metrics.csv";
    private volatile boolean running = true;

    @Override
    public void run() {
        while (running) {
            try {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                dateFormat.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata"));
                String timestamp = dateFormat.format(new java.util.Date());

                double cpuUsage = 10 + (random.nextDouble() * 80);
                double memoryUsage = 20 + (random.nextDouble() * 70);
                double diskUsage = 30 + (random.nextDouble() * 60);

                Map<String, Double> thresholds = repository.getThresholdSettings();
                
                Metrics metrics = new Metrics(timestamp, cpuUsage, memoryUsage, diskUsage);
                metrics.setAlarm(
                    cpuUsage > thresholds.get("cpu") || 
                    memoryUsage > thresholds.get("memory") || 
                    diskUsage > thresholds.get("disk")
                );
                repository.save(metrics);
                appendToCsv(metrics);

                if (System.currentTimeMillis() % (7 * 24 * 60 * 60 * 1000) == 0) {
                    repository.cleanupOldAlarms();
                }

                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public void stop() {
        running = false;
    }

    private synchronized void appendToCsv(Metrics metrics) {
        String csvLine = String.format("%s,%.2f,%.2f,%.2f,%b\n",
                metrics.getTimestamp(), 
                metrics.getCpuUsage(), 
                metrics.getMemoryUsage(), 
                metrics.getDiskUsage(),
                metrics.isAlarm());

        try {
            Files.write(Paths.get(CSV_FILE_PATH), csvLine.getBytes(), 
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("❌ Error writing to CSV file: " + e.getMessage());
        }
    }
}

class MetricsHttpServer {
    private static HttpServer server;
    private static final MetricsRepository repository = new MetricsRepository();
    private static final ExecutorService executor = Executors.newFixedThreadPool(10);
    private static final ObjectMapper mapper = new ObjectMapper();

    public static void start() {
        try {
            System.out.println("Attempting to create server on port 8081...");
            System.out.println("Available processors: " + Runtime.getRuntime().availableProcessors());
            
            server = HttpServer.create(new InetSocketAddress(8081), 0);
            System.out.println("Server instance created: " + server);
            
            server.createContext("/test", exchange -> {
                System.out.println("\n=== Received Request ===");
                System.out.println("Method: " + exchange.getRequestMethod());
                System.out.println("URI: " + exchange.getRequestURI());
                System.out.println("Headers: " + exchange.getRequestHeaders());
                
                String response = "Server is working!";
                exchange.getResponseHeaders().set("Content-Type", "text/plain");
                exchange.sendResponseHeaders(200, response.getBytes().length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                    System.out.println("Sent response: " + response);
                }
            });
            
            System.out.println("Registered /test endpoint");
            
            server.createContext("/api/login", new LoginHandler());
            server.createContext("/api/alarms", new AlarmsHandler());
            server.createContext("/api/alarms/acknowledge", new AcknowledgeHandler());
            server.createContext("/api/alarms/settings", new AlarmSettingsHandler());
            server.createContext("/api/metrics/latest", new LatestMetricsHandler());
            server.createContext("/api/metrics/download", new DownloadMetricsHandler());
            server.createContext("/api/metrics/range", new TimeRangeMetricsHandler());
            
            server.setExecutor(executor);
            server.start();
            System.out.println("🚀 Server started successfully on port 8081");
            System.out.println("Server address: " + server.getAddress());
            
        } catch (BindException e) {
            System.err.println("❌ Port 8081 is already in use. Please stop any other services using this port.");
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("❌ Failed to start server: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void setCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        setCorsHeaders(exchange);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, response.getBytes().length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }

    public static void stop() {
        if (server != null) {
            server.stop(0);
            executor.shutdown();
            System.out.println("✅ Server stopped.");
        }
    }

    static abstract class BaseHandler implements HttpHandler {
        protected void sendJsonResponse(HttpExchange exchange, int statusCode, Object response) throws IOException {
            String json = mapper.writeValueAsString(response);
            setCorsHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, json.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(json.getBytes());
            }
        }
        
        protected void handleError(HttpExchange exchange, Exception e) throws IOException {
            String errorJson = mapper.writeValueAsString(
                Map.of("error", e.getMessage(), "timestamp", LocalDateTime.now().toString())
            );
            setCorsHeaders(exchange);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(500, errorJson.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(errorJson.getBytes());
            }
        }
        
        protected Map<String, String> parseQuery(String query) {
            Map<String, String> params = new HashMap<>();
            if (query != null) {
                for (String param : query.split("&")) {
                    String[] pair = param.split("=");
                    if (pair.length > 1) {
                        params.put(pair[0], URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
                    }
                }
            }
            return params;
        }
        
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                    setCorsHeaders(exchange);
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }
                
                handleRequest(exchange);
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
        
        protected abstract void handleRequest(HttpExchange exchange) throws IOException;
    }

    static class LoginHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            try {
                System.out.println("\n=== Login Request ===");
                System.out.println("Method: " + exchange.getRequestMethod());
                
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    System.out.println("Error: Method not allowed");
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                InputStream requestBody = exchange.getRequestBody();
                String body = new String(requestBody.readAllBytes(), StandardCharsets.UTF_8);
                System.out.println("Request body: " + body);

                try {
                    Map<?, ?> credentials = mapper.readValue(body, Map.class);
                    System.out.println("Parsed credentials: " + credentials);

                    String username = (String) credentials.get("username");
                    String password = (String) credentials.get("password");

                    if (username == null || password == null) {
                        System.out.println("Error: Missing username or password");
                        sendJsonResponse(exchange, 400, Map.of("error", "Username and password are required"));
                        return;
                    }

                    System.out.println("Attempting to authenticate user: " + username);
                    AuthService.User user = AuthService.authenticate(username, password);

                    if (user != null) {
                        System.out.println("Authentication successful for user: " + username);
                        Map<String, Object> response = new HashMap<>();
                        response.put("id", user.getId());
                        response.put("username", user.getUsername());
                        response.put("role", user.getRole());
                        response.put("email", user.getEmail());
                        response.put("phone", user.getPhone());
                        
                        sendJsonResponse(exchange, 200, response);
                    } else {
                        System.out.println("Authentication failed for user: " + username);
                        sendJsonResponse(exchange, 401, Map.of("error", "Invalid credentials"));
                    }
                } catch (Exception e) {
                    System.out.println("Error processing request: " + e.getMessage());
                    e.printStackTrace();
                    handleError(exchange, e);
                }
            } catch (Exception e) {
                System.out.println("Unexpected error in login handler: " + e.getMessage());
                e.printStackTrace();
                handleError(exchange, e);
            }
        }
    }

    static class AlarmsHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
                String start = URLDecoder.decode(params.getOrDefault("start", ""), "UTF-8");
                String end = URLDecoder.decode(params.getOrDefault("end", ""), "UTF-8");
                Integer userId = params.containsKey("userId") ? 
                    Integer.parseInt(params.get("userId")) : null;
                
                if (start.isEmpty() || end.isEmpty()) {
                    System.out.println("⚠️ Received empty time range parameters for alarms");
                    sendJsonResponse(exchange, 200, Collections.emptyList());
                    return;
                }
                
                List<Metrics> alarms = repository.findAlarmsByTimeRange(start, end, userId);
                sendJsonResponse(exchange, 200, alarms);
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
    }

    static class AcknowledgeHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                InputStream requestBody = exchange.getRequestBody();
                String body = new String(requestBody.readAllBytes(), StandardCharsets.UTF_8);
                Map<?, ?> request = mapper.readValue(body, Map.class);
                
                int alarmId = ((Number) request.get("alarmId")).intValue();
                int userId = ((Number) request.get("userId")).intValue();
                
                repository.acknowledgeAlarm(alarmId, userId);
                sendJsonResponse(exchange, 200, Map.of("success", true));
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
    }

    static class AlarmSettingsHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    int retentionDays = repository.getRetentionDays();
                    Map<String, Double> thresholds = repository.getThresholdSettings();
                    
                    Map<String, Object> response = new HashMap<>();
                    response.put("retention_days", retentionDays);
                    response.putAll(thresholds);
                    
                    sendJsonResponse(exchange, 200, response);
                } 
                else if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    InputStream requestBody = exchange.getRequestBody();
                    String body = new String(requestBody.readAllBytes(), StandardCharsets.UTF_8);
                    Map<?, ?> request = mapper.readValue(body, Map.class);
                    
                    if (request.containsKey("retention_days")) {
                        int days = ((Number) request.get("retention_days")).intValue();
                        repository.setRetentionDays(days);
                    }
                    
                    if (request.containsKey("cpu_threshold") || 
                        request.containsKey("memory_threshold") || 
                        request.containsKey("disk_threshold")) {
                        
                        double cpu = request.containsKey("cpu_threshold") ? 
                            ((Number) request.get("cpu_threshold")).doubleValue() : 50;
                        double memory = request.containsKey("memory_threshold") ? 
                            ((Number) request.get("memory_threshold")).doubleValue() : 50;
                        double disk = request.containsKey("disk_threshold") ? 
                            ((Number) request.get("disk_threshold")).doubleValue() : 50;
                            
                        repository.setThresholdSettings(cpu, memory, disk);
                    }
                    
                    sendJsonResponse(exchange, 200, Map.of("success", true));
                }
                else {
                    exchange.sendResponseHeaders(405, -1);
                }
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
    }

    static class LatestMetricsHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                List<Metrics> metricsList = repository.findAll();
                sendJsonResponse(exchange, 200, metricsList);
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
    }

    static class DownloadMetricsHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                byte[] csvData = Files.readAllBytes(Paths.get("metrics.csv"));
                exchange.getResponseHeaders().set("Content-Type", "text/csv");
                exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=metrics.csv");
                setCorsHeaders(exchange);
                exchange.sendResponseHeaders(200, csvData.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(csvData);
                }
            } catch (IOException e) {
                handleError(exchange, e);
            }
        }
    }

    static class TimeRangeMetricsHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            try {
                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
                String startTime = params.get("start");
                String endTime = params.get("end");

                if (startTime == null || endTime == null || startTime.isEmpty() || endTime.isEmpty()) {
                    System.out.println("⚠️ Received empty time range parameters");
                    sendJsonResponse(exchange, 200, Collections.emptyList());
                    return;
                }

                startTime = URLDecoder.decode(startTime, "UTF-8");
                endTime = URLDecoder.decode(endTime, "UTF-8");
                
                System.out.println("Received time range request: " + startTime + " to " + endTime);

                List<Metrics> metricsList = repository.findByTimeRange(startTime, endTime);
                sendJsonResponse(exchange, 200, metricsList);
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
    }
}
