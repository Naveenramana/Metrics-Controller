package com.example.project2metrics;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class DownloadMetricsHandler implements HttpHandler {
    private static final String CSV_FILE_PATH = "metrics.csv";

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            return;
        }

        byte[] csvBytes = Files.readAllBytes(Paths.get(CSV_FILE_PATH));
        exchange.getResponseHeaders().set("Content-Type", "text/csv");
        exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=metrics.csv");
        exchange.sendResponseHeaders(200, csvBytes.length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(csvBytes);
        }
    }
}
