package org.sasanlabs.shared.sanitizer;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

/**
 * URL Validator with intentional bypasses for SAST testing.
 * Pattern 1: Validates surface-level URL properties but misses SSRF bypasses.
 */
public class URLValidator {

    private static final List<String> BLOCKED_HOSTS = Arrays.asList(
            "169.254.169.254",      // AWS metadata
            "metadata.google.internal", // GCP metadata
            "100.100.100.200"       // Alibaba metadata
    );

    private static final List<String> ALLOWED_PROTOCOLS = Arrays.asList(
            "http", "https"
    );

    /**
     * Validates a URL for SSRF safety.
     * VULNERABLE: Checks string hostname but doesn't resolve DNS.
     * Bypasses: DNS rebinding, IPv6 (::ffff:169.254.169.254), octal (0251.0376.0251.0376),
     * decimal (2852039166), shorthand (169.254.169.254 as 169.16689150).
     */
    public static boolean isAllowed(String urlString) {
        if (urlString == null) return false;
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol().toLowerCase();
            String host = url.getHost().toLowerCase();

            // Check protocol
            if (!ALLOWED_PROTOCOLS.contains(protocol)) {
                return false;
            }

            // Check against blocked hosts (string comparison only — no DNS resolution)
            for (String blocked : BLOCKED_HOSTS) {
                if (host.equals(blocked)) {
                    return false;
                }
            }

            // Block localhost string but not 127.0.0.1 variants
            if (host.equals("localhost")) {
                return false;
            }

            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /**
     * Validates URL and extracts host.
     * VULNERABLE: Returns the pre-resolution hostname, which may differ from actual target.
     */
    public static String extractValidatedHost(String urlString) {
        if (!isAllowed(urlString)) {
            throw new IllegalArgumentException("URL not allowed: " + urlString);
        }
        try {
            return new URL(urlString).getHost();
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Malformed URL", e);
        }
    }
}
