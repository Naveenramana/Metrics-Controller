
package com.example.project2metrics;

public class Metrics {
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
