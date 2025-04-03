package com.example.project2metrics;

import java.util.Map;  
import java.util.Random;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

public class MetricsCollector implements Runnable {
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
            System.err.println(" Error writing to CSV file: " + e.getMessage());
        }
    }
}
