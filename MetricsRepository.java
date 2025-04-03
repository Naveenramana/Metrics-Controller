package com.example.project2metrics;

import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.TimeZone;

public class MetricsRepository {
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

            System.out.println(" Metrics saved: " + metrics.getTimestamp());
        } catch (SQLException e) {
            System.err.println(" Error saving metrics: " + e.getMessage());
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
            System.err.println(" Error fetching metrics: " + e.getMessage());
        }
        return metricsList;
    }

    public List<Metrics> findAlarmsByTimeRange(String startTime, String endTime, Integer userId) {
        List<Metrics> alarms = new ArrayList<>();
        
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
            System.err.println(" Error fetching alarms: " + e.getMessage());
        }
        return alarms;
    }

    public List<Metrics> findByTimeRange(String startTime, String endTime) {
        List<Metrics> metricsList = new ArrayList<>();
        
        if (startTime == null || startTime.isEmpty() || endTime == null || endTime.isEmpty()) {
            System.out.println(" Empty time range parameters - returning empty results");
            return metricsList;
        }

        String sql = "SELECT * FROM metrics WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp ASC";

        try (Connection connection = DriverManager.getConnection(DB_URL);
             PreparedStatement statement = connection.prepareStatement(sql)) {

            String formattedStartTime = formatTimestampForSQLite(startTime);
            String formattedEndTime = formatTimestampForSQLite(endTime);

            statement.setString(1, formattedStartTime);
            statement.setString(2, formattedEndTime);
            
            ResultSet resultSet = statement.executeQuery();

            while (resultSet.next()) {
                Metrics metrics = createMetricFromResultSet(resultSet);
                metricsList.add(metrics);
            }
        } catch (SQLException e) {
            System.err.println(" Error fetching metrics by time range: " + e.getMessage());
        }
        return metricsList;
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
            
            System.out.println(" Acknowledged alarm ID: " + alarmId + " by user ID: " + userId);
        } catch (SQLException e) {
            System.err.println(" Error acknowledging alarm: " + e.getMessage());
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
            System.err.println(" Error getting threshold settings: " + e.getMessage());
            return Map.of("cpu", 50.0, "memory", 50.0, "disk", 50.0);
        }
    }

    public void cleanupOldAlarms() {
        String sql = "DELETE FROM metrics WHERE is_alarm = TRUE AND " +
                     "acknowledged_at < date('now', '-' || ? || ' days')";
                         
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setInt(1, getRetentionDays());
            int deleted = stmt.executeUpdate();
            System.out.println(" Cleaned up " + deleted + " old alarms");
        } catch (SQLException e) {
            System.err.println(" Cleanup failed: " + e.getMessage());
        }
    }

    public int getRetentionDays() {
        String sql = "SELECT retention_days FROM alarm_settings LIMIT 1";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            
            return rs.next() ? rs.getInt("retention_days") : 30;
        } catch (SQLException e) {
            System.err.println(" Error getting retention days: " + e.getMessage());
            return 30;
        }
    }

    public void setRetentionDays(int days) {
        String sql = "UPDATE alarm_settings SET retention_days = ? WHERE id = 1";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            
            stmt.setInt(1, days);
            stmt.executeUpdate();
            System.out.println(" Updated retention days to: " + days);
        } catch (SQLException e) {
            System.err.println(" Error setting retention days: " + e.getMessage());
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
            
            System.out.println(" Thresholds updated to CPU: " + cpu + "%, Memory: " + memory + "%, Disk: " + disk + "%");
        } catch (SQLException e) {
            System.err.println(" Error updating thresholds: " + e.getMessage());
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
            System.err.println(" Empty or null timestamp");
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
            System.err.println(" Error formatting timestamp: " + timestamp);
            System.err.println("Error details: " + e.getMessage());
            return timestamp;
        }
    }
}
