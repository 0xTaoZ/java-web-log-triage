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
        Map<String, Integer> clientErrorSourceCounts = new LinkedHashMap<>();
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
                if (isClientError(entry.statusCode())) {
                    increment(clientErrorSourceCounts, entry.ipAddress());
                }

                Finding finding = SuspiciousRequestDetector.classify(entry.path());
                if (finding != null) {
                    findings.add(finding);
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
                Collections.unmodifiableMap(new LinkedHashMap<>(clientErrorSourceCounts)),
                List.copyOf(findings));
    }

    private static boolean isClientError(int statusCode) {
        return statusCode >= 400 && statusCode <= 499;
    }

    private static <T> void increment(Map<T, Integer> counts, T key) {
        counts.put(key, counts.getOrDefault(key, 0) + 1);
    }
}
