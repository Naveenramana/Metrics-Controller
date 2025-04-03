
package com.example.project2metrics;
import com.example.project2metrics.MetricsCollector;
import com.example.project2metrics.MetricsHttpServer;
import com.example.project2metrics.DatabaseInitializer;
import com.example.project2metrics.AuthService;
public class MetricsApplication {
    public static void main(String[] args) {
        DatabaseInitializer.initializeDatabase();
        DatabaseInitializer.migrateToV2();
        
        
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
