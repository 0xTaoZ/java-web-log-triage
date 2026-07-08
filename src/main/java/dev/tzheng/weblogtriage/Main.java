package dev.tzheng.weblogtriage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 1) {
            System.err.println("Usage: java -cp build/classes dev.tzheng.weblogtriage.Main <access-log>");
            System.exit(2);
        }

        TriageSummary summary = TriageAnalyzer.analyze(Files.readAllLines(Path.of(args[0])));
        System.out.print(ReportFormatter.format(summary));
    }
}

