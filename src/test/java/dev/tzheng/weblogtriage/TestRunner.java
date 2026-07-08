package dev.tzheng.weblogtriage;

public final class TestRunner {
    public static void main(String[] args) {
        parsesCombinedAccessLogLine();
        flagsSuspiciousRequestPaths();
        summarizesLogLines();
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

    private static void flagsSuspiciousRequestPaths() {
        assertEquals(
                "path traversal probe",
                SuspiciousRequestDetector.classify("/../../etc/passwd").reason(),
                "traversal reason");
        assertEquals(
                "web shell probe",
                SuspiciousRequestDetector.classify("/uploads/cmd.php").reason(),
                "shell reason");
        assertEquals(
                "admin login probe",
                SuspiciousRequestDetector.classify("/admin/login.php").reason(),
                "admin reason");
        assertEquals(
                "wordpress probe",
                SuspiciousRequestDetector.classify("/wp-login.php").reason(),
                "wordpress reason");
        assertEquals(null, SuspiciousRequestDetector.classify("/assets/site.css"), "benign path");
    }

    private static void summarizesLogLines() {
        String first = "198.51.100.23 - - [08/Jul/2026:10:15:42 +0000] "
                + "\"GET /admin/login.php HTTP/1.1\" 404 532 \"-\" \"curl/8.1\"";
        String second = "203.0.113.10 - - [08/Jul/2026:10:16:01 +0000] "
                + "\"POST /api/orders HTTP/1.1\" 200 1210 \"-\" \"Mozilla/5.0\"";
        String third = "198.51.100.23 - - [08/Jul/2026:10:16:22 +0000] "
                + "\"GET /../../etc/passwd HTTP/1.1\" 400 64 \"-\" \"curl/8.1\"";

        TriageSummary summary = TriageAnalyzer.analyze(java.util.List.of(first, second, third, "bad line"));

        assertEquals(3, summary.parsedLines(), "parsed lines");
        assertEquals(1, summary.malformedLines(), "malformed lines");
        assertEquals(2, summary.sourceIpCounts().get("198.51.100.23"), "ip count");
        assertEquals(1, summary.statusCodeCounts().get(404), "404 count");
        assertEquals(2, summary.findings().size(), "finding count");
        assertEquals("admin login probe", summary.findings().getFirst().reason(), "first finding");
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (expected == null && actual == null) {
            return;
        }
        if (expected == null || !expected.equals(actual)) {
            throw new AssertionError(label + ": expected " + expected + " but got " + actual);
        }
    }
}
