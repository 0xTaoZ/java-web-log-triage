package dev.tzheng.weblogtriage;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ApacheLogParser {
    private static final Pattern COMBINED_LOG = Pattern.compile(
            "^(\\S+) \\S+ \\S+ \\[([^]]+)] \"(\\S+) ([^\"]+) HTTP/[^\"]+\" (\\d{3}) (\\S+) \"([^\"]*)\" \"([^\"]*)\"$");

    private ApacheLogParser() {
    }

    public static LogEntry parse(String line) {
        Matcher matcher = COMBINED_LOG.matcher(line);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("unsupported access log line: " + line);
        }

        return new LogEntry(
                matcher.group(1),
                matcher.group(2),
                matcher.group(3),
                matcher.group(4),
                Integer.parseInt(matcher.group(5)),
                parseBytes(matcher.group(6)),
                matcher.group(7),
                matcher.group(8));
    }

    private static int parseBytes(String value) {
        if ("-".equals(value)) {
            return 0;
        }
        return Integer.parseInt(value);
    }
}

