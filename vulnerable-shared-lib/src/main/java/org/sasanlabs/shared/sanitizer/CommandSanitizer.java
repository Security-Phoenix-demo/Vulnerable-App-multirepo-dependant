package org.sasanlabs.shared.sanitizer;

import java.util.Arrays;
import java.util.List;

/**
 * Command Sanitizer with intentional bypasses for SAST testing.
 * Pattern 1: Blocks common separators but misses critical ones.
 */
public class CommandSanitizer {

    // Intentionally incomplete blacklist
    private static final List<String> BLOCKED_CHARS = Arrays.asList(
            ";", "&", "&&", "||", "|"
    );

    /**
     * Sanitizes input for OS command execution.
     * VULNERABLE: Misses newline (\n), carriage return (\r), backtick (`),
     * $() subshell syntax, and %0a URL-encoded newline.
     */
    public static String sanitize(String input) {
        if (input == null) return null;
        String result = input;
        for (String blocked : BLOCKED_CHARS) {
            result = result.replace(blocked, "");
        }
        return result;
    }

    /**
     * Validates an IP address for ping commands.
     * VULNERABLE: Regex allows trailing characters after a valid IP prefix.
     * Input "127.0.0.1\ncat /etc/passwd" matches because find() not matches() is used internally,
     * and the regex doesn't anchor end-of-string properly.
     */
    public static boolean isValidIPAddress(String input) {
        if (input == null) return false;
        // Intentionally uses .* at end instead of $, allowing appended commands
        return input.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*");
    }

    /**
     * Builds a ping command.
     * VULNERABLE: Uses sanitize() which is bypassable, then concatenates into command.
     */
    public static String buildPingCommand(String target) {
        String sanitized = sanitize(target);
        if (!isValidIPAddress(sanitized)) {
            throw new IllegalArgumentException("Invalid IP address");
        }
        return "ping -c 2 " + sanitized;
    }
}
