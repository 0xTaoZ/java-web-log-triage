package dev.tzheng.weblogtriage;

import java.util.Locale;

public final class SuspiciousRequestDetector {
    private SuspiciousRequestDetector() {
    }

    public static Finding classify(String path) {
        String lowerPath = path.toLowerCase(Locale.ROOT);
        if (lowerPath.contains("../") || lowerPath.contains("%2e%2e")) {
            return new Finding("path traversal probe", path);
        }
        if (lowerPath.endsWith(".php")
                && (lowerPath.contains("cmd") || lowerPath.contains("shell") || lowerPath.contains("upload"))) {
            return new Finding("web shell probe", path);
        }
        if (lowerPath.contains("/admin") || lowerPath.contains("/login")) {
            return new Finding("admin login probe", path);
        }
        if (lowerPath.contains("wp-login") || lowerPath.contains("xmlrpc.php") || lowerPath.contains("/wp-admin")) {
            return new Finding("wordpress probe", path);
        }
        return null;
    }
}

