package dev.tzheng.weblogtriage;

public record LogEntry(
        String ipAddress,
        String timestamp,
        String method,
        String path,
        int statusCode,
        int bytesSent,
        String referer,
        String userAgent) {
}

