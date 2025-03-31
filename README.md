# Metrics-Controller



## System Overview

The application consists of:
1. **Backend**: Java-based server that collects metrics, stores them in a database, and provides REST APIs
2. **Frontend**: React-based web interface for visualization and management
3. **Database**: SQLite database for storing metrics, users, and settings

## Key Components

### Backend Components

1. **Metrics Collector**:
   - Runs as a separate thread
   - Simulates system metrics (CPU, memory, disk usage) with random values
   - Checks against thresholds to determine if metrics should trigger alarms
   - Stores metrics in database and CSV file

2. **HTTP Server**:
   - Handles all API requests from frontend
   - Implements REST endpoints for:
     - Authentication (/api/login)
     - Metrics retrieval (/api/metrics/latest, /api/metrics/range)
     - Alarm management (/api/alarms, /api/alarms/acknowledge)
     - Settings (/api/alarms/settings)
     - Data export (/api/metrics/download)

3. **Database Layer**:
   - SQLite database with tables for:
     - Users (username, password, role)
     - Metrics (timestamp, CPU, memory, disk usage, alarm status)
     - Alarm settings (thresholds, retention period)

### Frontend Components

1. **Authentication System**:
   - Login page with username/password
   - Role-based access (admin vs operator)
   - Session management using localStorage

2. **Dashboard Views**:
   - **Admin Dashboard**: Full access to all features
   - **Operator Dashboard**: Limited to viewing and acknowledging alarms

3. **Visualization**:
   - Line charts showing metrics over time
   - Pie charts showing current resource usage
   - Alarm lists with sorting capabilities

4. **Features**:
   - Time range filtering for metrics and alarms
   - Alarm acknowledgment system
   - Threshold configuration
   - Data retention settings
   - CSV export functionality

## Workflow

1. **Data Collection**:
   - Backend collects simulated metrics every 5 seconds
   - Checks if metrics exceed configured thresholds
   - Stores metrics in database and marks alarms

2. **User Interaction**:
   - User logs in with credentials
   - Based on role, sees appropriate dashboard
   - Views real-time metrics and alarms
   - Can acknowledge alarms (operators) or configure settings (admins)

3. **Data Management**:
   - Old alarms are automatically cleaned up based on retention period
   - Settings changes immediately affect new metrics collection

## Technical Highlights

1. **Backend**:
   - Lightweight HTTP server using Java's built-in HttpServer
   - SQLite database for simple, file-based storage
   - Thread-safe metrics collection
   - Comprehensive error handling

2. **Frontend**:
   - React hooks for state management
   - Chart.js for data visualization
   - Axios for API communication
   - Responsive design with CSS

3. **Integration**:
   - REST API with JSON payloads
   - CORS support for frontend-backend communication
   - Consistent data formats between components

 **Use Cases**

This system could be used for:
- Monitoring server health
- Identifying resource bottlenecks
- Tracking system performance over time
- Alerting IT staff to potential issues
- Generating reports on system usage
