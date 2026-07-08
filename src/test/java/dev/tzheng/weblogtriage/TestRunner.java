package dev.tzheng.weblogtriage;

public final class TestRunner {
    public static void main(String[] args) {
        parsesCombinedAccessLogLine();
        System.out.println("All tests passed.");
    }

    private static void parsesCombinedAccessLogLine() {
        String line = "198.51.100.23 - - [08/Jul/2026:10:15:42 +0000] "
                + "\"GET /admin/login.php HTTP/1.1\" 404 532 \"-\" \"curl/8.1\"";

        LogEntry entry = ApacheLogParser.parse(line);

        assertEquals("198.51.100.23", entry.ipAddress(), "ip address");
        assertEquals("08/Jul/2026:10:15:42 +0000", entry.timestamp(), "timestamp");
        assertEquals("GET", entry.method(), "method");
        assertEquals("/admin/login.php", entry.path(), "path");
        assertEquals(404, entry.statusCode(), "status");
        assertEquals(532, entry.bytesSent(), "bytes sent");
        assertEquals("curl/8.1", entry.userAgent(), "user agent");
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (!expected.equals(actual)) {
            throw new AssertionError(label + ": expected " + expected + " but got " + actual);
        }
    }
}

