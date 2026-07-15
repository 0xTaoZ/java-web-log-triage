package dev.tzheng.weblogtriage;

import java.util.Map;

public final class ReportFormatter {
    private ReportFormatter() {
    }

    public static String format(TriageSummary summary) {
        StringBuilder report = new StringBuilder();
        report.append("Web log triage summary\n");
        report.append("======================\n");
        report.append("Parsed lines: ").append(summary.parsedLines()).append('\n');
        report.append("Malformed lines: ").append(summary.malformedLines()).append('\n');

        appendCounts(report, "\nSource IPs", summary.sourceIpCounts());
        appendCounts(report, "\nStatus codes", summary.statusCodeCounts());
        appendCounts(report, "\nClient error sources", summary.clientErrorSourceCounts());

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

    private static <T> void appendCounts(StringBuilder report, String title, Map<T, Integer> counts) {
        report.append(title).append('\n');
        if (counts.isEmpty()) {
            report.append("- none\n");
            return;
        }
        for (Map.Entry<T, Integer> entry : counts.entrySet()) {
            report.append("- ").append(entry.getKey()).append(": ").append(entry.getValue()).append('\n');
        }
    }
}
