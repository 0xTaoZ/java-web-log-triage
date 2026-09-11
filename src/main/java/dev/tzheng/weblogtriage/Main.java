package dev.tzheng.weblogtriage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws IOException {
        int limit = 0;
        int pathIndex = 0;
        if (args.length == 3 && "--top".equals(args[0])) {
            limit = parseLimit(args[1]);
            pathIndex = 2;
        } else if (args.length != 1) {
            usage();
            System.exit(2);
        }

        TriageSummary summary = TriageAnalyzer.analyze(Files.readAllLines(Path.of(args[pathIndex])));
        System.out.print(ReportFormatter.format(summary, limit));
    }

    private static int parseLimit(String value) {
        try {
            int limit = Integer.parseInt(value);
            if (limit > 0) {
                return limit;
            }
        } catch (NumberFormatException ignored) {
            // fall through to usage
        }
        usage();
        System.exit(2);
        return 0;
    }

    private static void usage() {
        System.err.println("Usage: java -cp build/classes dev.tzheng.weblogtriage.Main [--top N] <access-log>");
    }
}
