package org.sasanlabs.shared.sanitizer;

import java.util.regex.Pattern;

/**
 * Input Validator with intentional vulnerabilities for SAST testing.
 * Pattern 1: Regex-based validators with ReDoS and bypass issues.
 */
public class InputValidator {

    /**
     * Validates filenames for path traversal safety.
     * VULNERABLE: Doesn't handle URL-encoded sequences (%2e%2e%2f),
     * null bytes (\0), or Unicode normalization bypasses.
     */
    public static boolean isValidFilename(String filename) {
        if (filename == null) return false;
        // Blocks ../ and ..\ but not encoded variants
        if (filename.contains("../") || filename.contains("..\\")) {
            return false;
        }
        // ReDoS-vulnerable regex: catastrophic backtracking on long filenames
        // with repeated dots like "a...............................x"
        return filename.matches("^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?(\\.([a-zA-Z0-9]+))*$");
    }

    /**
     * Validates email format.
     * VULNERABLE: ReDoS-vulnerable regex with nested quantifiers.
     * Input like "aaaaaaaaaaaaaaaaaa@" causes catastrophic backtracking.
     */
    public static boolean isValidEmail(String email) {
        if (email == null) return false;
        // Nested quantifiers cause exponential backtracking
        Pattern emailPattern = Pattern.compile(
                "^([a-zA-Z0-9]+[._-]?)*[a-zA-Z0-9]+@([a-zA-Z0-9]+[._-]?)*[a-zA-Z0-9]+\\.[a-zA-Z]{2,}$"
        );
        return emailPattern.matcher(email).matches();
    }

    /**
     * Sanitizes a filename by removing path separators.
     * VULNERABLE: Only removes forward slash and backslash, misses URL-encoded
     * variants and null bytes that can truncate the filename.
     */
    public static String sanitizeFilename(String filename) {
        if (filename == null) return null;
        return filename.replace("/", "").replace("\\", "");
    }

    /**
     * Validates that input matches an allowed pattern.
     * VULNERABLE: Uses user-controlled input as regex pattern — enables ReDoS.
     */
    public static boolean matchesPattern(String input, String pattern) {
        if (input == null || pattern == null) return false;
        return Pattern.compile(pattern).matcher(input).matches();
    }
}
