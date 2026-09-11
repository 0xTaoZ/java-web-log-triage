package dev.tzheng.weblogtriage;

import java.util.Comparator;
import java.util.Map;

public final class ReportFormatter {
    private ReportFormatter() {
    }

    public static String format(TriageSummary summary) {
        return format(summary, 0);
    }

    public static String format(TriageSummary summary, int limit) {
        StringBuilder report = new StringBuilder();
        report.append("Web log triage summary\n");
        report.append("======================\n");
        report.append("Parsed lines: ").append(summary.parsedLines()).append('\n');
        report.append("Malformed lines: ").append(summary.malformedLines()).append('\n');

        appendCounts(report, "\nSource IPs", summary.sourceIpCounts(), limit);
        appendCounts(report, "\nStatus codes", summary.statusCodeCounts(), limit);
        appendCounts(report, "\nMethod/status pairs", summary.methodStatusCounts(), limit);
        appendCounts(report, "\nClient error sources", summary.clientErrorSourceCounts(), limit);
        appendCounts(report, "\nServer error sources", summary.serverErrorSourceCounts(), limit);
        appendCounts(report, "\nUser agents", summary.userAgentCounts(), limit);

        report.append("\nFindings\n");
        if (summary.findings().isEmpty()) {
            report.append("- none\n");
        } else {
            for (Finding finding : summary.findings()) {
                report.append("- ").append(finding.reason()).append(" -> ").append(finding.path()).append('\n');
            }
        }

        return report.toString();
    }

    private static <T> void appendCounts(StringBuilder report, String title, Map<T, Integer> counts, int limit) {
        report.append(title).append('\n');
        if (counts.isEmpty()) {
            report.append("- none\n");
            return;
        }
        if (limit <= 0) {
            for (Map.Entry<T, Integer> entry : counts.entrySet()) {
                appendCount(report, entry);
            }
            return;
        }
        int shown = limit > 0 ? Math.min(limit, counts.size()) : counts.size();
        counts.entrySet().stream()
                .sorted(Map.Entry.<T, Integer>comparingByValue(Comparator.reverseOrder()))
                .limit(shown)
                .forEach(entry -> appendCount(report, entry));
        if (shown < counts.size()) {
            report.append("- ... ").append(counts.size() - shown).append(" more\n");
        }
    }

    private static <T> void appendCount(StringBuilder report, Map.Entry<T, Integer> entry) {
        report.append("- ")
                .append(entry.getKey())
                .append(": ")
                .append(entry.getValue())
                .append('\n');
    }
}
