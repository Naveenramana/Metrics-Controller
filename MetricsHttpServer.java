package com.example.project2metrics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public class MetricsHttpServer {
    private static HttpServer server;
    private static final MetricsRepository repository = new MetricsRepository();
    private static final ExecutorService executor = Executors.newFixedThreadPool(10);
    private static final ObjectMapper mapper = new ObjectMapper();

    public static void start() {
        try {
            server = HttpServer.create(new InetSocketAddress(8081), 0);
            
            server.createContext("/api/login", new LoginHandler());
            server.createContext("/api/alarms", new AlarmsHandler());
            server.createContext("/api/alarms/acknowledge", new AcknowledgeHandler());
            server.createContext("/api/alarms/settings", new AlarmSettingsHandler());
            server.createContext("/api/metrics/latest", new LatestMetricsHandler());
            server.createContext("/api/metrics/range", new TimeRangeMetricsHandler());
            
            server.setExecutor(executor);
            server.start();
            System.out.println(" Server started successfully on port 8081");
        } catch (IOException e) {
            System.err.println(" Failed to start server: " + e.getMessage());
        }
    }

    public static void stop() {
        if (server != null) {
            server.stop(0);
            executor.shutdown();
            System.out.println(" Server stopped.");
        }
    }

     private static void setCorsHeaders(HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", 
            origin != null ? origin : "http://localhost:5173");
        exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().set("Access-Control-Allow-Credentials", "true");
        exchange.getResponseHeaders().set("Vary", "Origin");
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
                Map.of("error", e.getMessage(), "timestamp", new Date().toString())
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
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                InputStream requestBody = exchange.getRequestBody();
                String body = new String(requestBody.readAllBytes(), StandardCharsets.UTF_8);
                Map<?, ?> credentials = mapper.readValue(body, Map.class);

                String username = (String) credentials.get("username");
                String password = (String) credentials.get("password");

                AuthService.User user = AuthService.authenticate(username, password);
                if (user != null) {
                    Map<String, Object> response = new HashMap<>();
                    response.put("id", user.getId());
                    response.put("username", user.getUsername());
                    response.put("role", user.getRole());
                    response.put("email", user.getEmail());
                    response.put("phone", user.getPhone());
                    sendJsonResponse(exchange, 200, response);
                } else {
                    sendJsonResponse(exchange, 401, Map.of("error", "Invalid credentials"));
                }
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
    }

    static class AlarmsHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
                String start = params.getOrDefault("start", "");
                String end = params.getOrDefault("end", "");
                Integer userId = params.containsKey("userId") ? Integer.parseInt(params.get("userId")) : null;

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
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

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
                    
                    if (request.containsKey("cpu_threshold") || request.containsKey("memory_threshold") || 
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
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                List<Metrics> metricsList = repository.findAll();
                sendJsonResponse(exchange, 200, metricsList);
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
    }

    static class TimeRangeMetricsHandler extends BaseHandler {
        @Override
        protected void handleRequest(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
                String startTime = params.get("start");
                String endTime = params.get("end");

                List<Metrics> metricsList = repository.findByTimeRange(startTime, endTime);
                sendJsonResponse(exchange, 200, metricsList);
            } catch (Exception e) {
                handleError(exchange, e);
            }
        }
    }
}
