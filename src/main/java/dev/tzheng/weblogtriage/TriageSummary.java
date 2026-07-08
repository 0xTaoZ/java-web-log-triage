package dev.tzheng.weblogtriage;

import java.util.List;
import java.util.Map;

public record TriageSummary(
        int parsedLines,
        int malformedLines,
        Map<String, Integer> sourceIpCounts,
        Map<Integer, Integer> statusCodeCounts,
        List<Finding> findings) {
}

