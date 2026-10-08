package dev.tzheng.weblogtriage;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ApacheLogParser {
    // Apache and nginx escape a double quote inside a field as \", so a quoted
    // field is any run of non-quote characters or backslash escapes.
    private static final String QUOTED = "\"((?:[^\"\\\\]|\\\\.)*)\"";

    private static final Pattern COMBINED_LOG = Pattern.compile(
            "^(\\S+) \\S+ \\S+ \\[([^]]+)] " + QUOTED + " (\\d{3}) (\\S+) " + QUOTED + " " + QUOTED + "$");

    // The version is optional: HTTP/0.9 style requests and some scanners send
    // only "METHOD path".
    private static final Pattern REQUEST_LINE = Pattern.compile("^(\\S+) (.+?)(?: HTTP/\\S+)?$");

    private ApacheLogParser() {
    }

    public static LogEntry parse(String line) {
        Matcher matcher = COMBINED_LOG.matcher(line);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("unsupported access log line: " + line);
        }

        String request = unescape(matcher.group(3));
        String method = "-";
        String path = request;
        Matcher requestMatcher = REQUEST_LINE.matcher(request);
        if (requestMatcher.matches()) {
            method = requestMatcher.group(1);
            path = requestMatcher.group(2);
        }

        return new LogEntry(
                matcher.group(1),
                matcher.group(2),
                method,
                path,
                Integer.parseInt(matcher.group(4)),
                parseBytes(matcher.group(5)),
                unescape(matcher.group(6)),
                unescape(matcher.group(7)));
    }

    private static long parseBytes(String value) {
        if ("-".equals(value)) {
            return 0;
        }
        return Long.parseLong(value);
    }

    private static String unescape(String value) {
        if (value.indexOf('\\') < 0) {
            return value;
        }
        StringBuilder result = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (current == '\\' && i + 1 < value.length()
                    && (value.charAt(i + 1) == '"' || value.charAt(i + 1) == '\\')) {
                result.append(value.charAt(++i));
            } else {
                result.append(current);
            }
        }
        return result.toString();
    }
}
