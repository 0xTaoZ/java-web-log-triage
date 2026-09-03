package dev.tzheng.weblogtriage;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class TriageAnalyzer {
    private TriageAnalyzer() {
    }

    public static TriageSummary analyze(List<String> lines) {
        int parsedLines = 0;
        int malformedLines = 0;
        Map<String, Integer> sourceIpCounts = new LinkedHashMap<>();
        Map<Integer, Integer> statusCodeCounts = new LinkedHashMap<>();
        Map<String, Integer> methodStatusCounts = new LinkedHashMap<>();
        Map<String, Integer> clientErrorSourceCounts = new LinkedHashMap<>();
        Map<String, Integer> serverErrorSourceCounts = new LinkedHashMap<>();
        Map<String, Integer> userAgentCounts = new LinkedHashMap<>();
        List<Finding> findings = new ArrayList<>();

        for (String line : lines) {
            if (line.isBlank()) {
                continue;
            }
            try {
                LogEntry entry = ApacheLogParser.parse(line);
                parsedLines++;
                increment(sourceIpCounts, entry.ipAddress());
                increment(statusCodeCounts, entry.statusCode());
                increment(methodStatusCounts, entry.method() + " " + entry.statusCode());
                increment(userAgentCounts, entry.userAgent());
                if (isClientError(entry.statusCode())) {
                    increment(clientErrorSourceCounts, entry.ipAddress());
                }
                if (isServerError(entry.statusCode())) {
                    increment(serverErrorSourceCounts, entry.ipAddress());
                }

                Finding finding = SuspiciousRequestDetector.classify(entry.path());
                if (finding != null) {
                    findings.add(finding);
                }
                Finding userAgentFinding = SuspiciousRequestDetector.classifyUserAgent(entry.userAgent());
                if (userAgentFinding != null) {
                    findings.add(userAgentFinding);
                }
            } catch (IllegalArgumentException ignored) {
                malformedLines++;
            }
        }

        return new TriageSummary(
                parsedLines,
                malformedLines,
                Collections.unmodifiableMap(new LinkedHashMap<>(sourceIpCounts)),
                Collections.unmodifiableMap(new LinkedHashMap<>(statusCodeCounts)),
                Collections.unmodifiableMap(new LinkedHashMap<>(methodStatusCounts)),
                Collections.unmodifiableMap(new LinkedHashMap<>(clientErrorSourceCounts)),
                Collections.unmodifiableMap(new LinkedHashMap<>(serverErrorSourceCounts)),
                Collections.unmodifiableMap(new LinkedHashMap<>(userAgentCounts)),
                List.copyOf(findings));
    }

    private static boolean isClientError(int statusCode) {
        return statusCode >= 400 && statusCode <= 499;
    }

    private static boolean isServerError(int statusCode) {
        return statusCode >= 500 && statusCode <= 599;
    }

    private static <T> void increment(Map<T, Integer> counts, T key) {
        counts.put(key, counts.getOrDefault(key, 0) + 1);
    }
}
