package dev.tzheng.weblogtriage;

public record LogEntry(
        String ipAddress,
        String timestamp,
        String method,
        String path,
        int statusCode,
        long bytesSent,
        String referer,
        String userAgent) {
}

