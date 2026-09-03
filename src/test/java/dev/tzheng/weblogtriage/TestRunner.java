package dev.tzheng.weblogtriage;

public final class TestRunner {
    public static void main(String[] args) {
        parsesCombinedAccessLogLine();
        flagsSuspiciousRequestPaths();
        flagsScannerUserAgents();
        summarizesLogLines();
        formatsSummaryReport();
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

    private static void flagsScannerUserAgents() {
        assertEquals(
                "scanner user agent",
                SuspiciousRequestDetector.classifyUserAgent("sqlmap/1.8.4").reason(),
                "sqlmap user agent reason");
        assertEquals(
                "scanner user agent",
                SuspiciousRequestDetector.classifyUserAgent("python-requests/2.31.0").reason(),
                "python requests user agent reason");
        assertEquals(null, SuspiciousRequestDetector.classifyUserAgent("Mozilla/5.0"), "browser user agent");
    }

    private static void summarizesLogLines() {
        String first = "198.51.100.23 - - [08/Jul/2026:10:15:42 +0000] "
                + "\"GET /admin/login.php HTTP/1.1\" 404 532 \"-\" \"curl/8.1\"";
        String second = "203.0.113.10 - - [08/Jul/2026:10:16:01 +0000] "
                + "\"POST /api/orders HTTP/1.1\" 200 1210 \"-\" \"Mozilla/5.0\"";
        String third = "198.51.100.23 - - [08/Jul/2026:10:16:22 +0000] "
                + "\"GET /../../etc/passwd HTTP/1.1\" 400 64 \"-\" \"curl/8.1\"";
        String fourth = "203.0.113.10 - - [08/Jul/2026:10:17:11 +0000] "
                + "\"POST /api/orders HTTP/1.1\" 502 91 \"-\" \"Mozilla/5.0\"";

        TriageSummary summary = TriageAnalyzer.analyze(java.util.List.of(first, second, third, fourth, "bad line", ""));

        assertEquals(4, summary.parsedLines(), "parsed lines");
        assertEquals(1, summary.malformedLines(), "malformed lines");
        assertEquals(2, summary.sourceIpCounts().get("198.51.100.23"), "ip count");
        assertEquals(1, summary.statusCodeCounts().get(404), "404 count");
        assertEquals(1, summary.methodStatusCounts().get("GET 404"), "GET 404 count");
        assertEquals(1, summary.methodStatusCounts().get("POST 502"), "POST 502 count");
        assertEquals(2, summary.clientErrorSourceCounts().get("198.51.100.23"), "client error source count");
        assertEquals(null, summary.clientErrorSourceCounts().get("203.0.113.10"), "non-error source count");
        assertEquals(1, summary.serverErrorSourceCounts().get("203.0.113.10"), "server error source count");
        assertEquals(null, summary.serverErrorSourceCounts().get("198.51.100.23"), "non-server-error source count");
        assertEquals(2, summary.userAgentCounts().get("curl/8.1"), "curl user agent count");
        assertEquals(2, summary.userAgentCounts().get("Mozilla/5.0"), "browser user agent count");
        assertEquals(4, summary.findings().size(), "finding count");
        assertEquals("admin login probe", summary.findings().getFirst().reason(), "first finding");
    }

    private static void formatsSummaryReport() {
        String line = "198.51.100.23 - - [08/Jul/2026:10:15:42 +0000] "
                + "\"GET /admin/login.php HTTP/1.1\" 404 532 \"-\" \"curl/8.1\"";
        TriageSummary summary = TriageAnalyzer.analyze(java.util.List.of(line));

        String report = ReportFormatter.format(summary);

        assertContains(report, "Parsed lines: 1", "parsed line report");
        assertContains(report, "Malformed lines: 0", "malformed line report");
        assertContains(report, "198.51.100.23: 1", "source ip report");
        assertContains(report, "404: 1", "status code report");
        assertContains(report, "Method/status pairs", "method status header");
        assertContains(report, "GET 404: 1", "method status report");
        assertContains(report, "Client error sources", "client error source header");
        assertContains(report, "198.51.100.23: 1", "client error source report");
        assertContains(report, "Server error sources", "server error source header");
        assertContains(report, "- none", "empty server error source report");
        assertContains(report, "User agents", "user agent header");
        assertContains(report, "curl/8.1: 1", "user agent report");
        assertContains(report, "admin login probe -> /admin/login.php", "finding report");
    }

    private static void assertEquals(Object expected, Object actual, String label) {
        if (expected == null && actual == null) {
            return;
        }
        if (expected == null || !expected.equals(actual)) {
            throw new AssertionError(label + ": expected " + expected + " but got " + actual);
        }
    }

    private static void assertContains(String text, String expected, String label) {
        if (!text.contains(expected)) {
            throw new AssertionError(label + ": expected report to contain " + expected + "\n" + text);
        }
    }
}
