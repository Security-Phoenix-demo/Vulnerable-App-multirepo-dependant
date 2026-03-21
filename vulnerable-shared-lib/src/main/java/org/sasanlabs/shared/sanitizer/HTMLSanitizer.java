package org.sasanlabs.shared.sanitizer;

import org.apache.commons.text.StringSubstitutor;
import java.util.HashMap;
import java.util.regex.Pattern;

/**
 * HTML Sanitizer with intentional bypasses for SAST testing.
 * Pattern 1: Broken sanitization + Pattern 5: Uses commons-text 1.8 (Text4Shell)
 */
public class HTMLSanitizer {

    // Intentionally incomplete — misses <svg>, <math>, <details>, <object>, event handlers
    private static final Pattern DANGEROUS_TAGS = Pattern.compile(
            "<(script|img|a|iframe|embed|form)(\\s|>|/)", Pattern.CASE_INSENSITIVE);

    private static final Pattern DANGEROUS_ATTRS = Pattern.compile(
            "\\s(on\\w+)\\s*=", Pattern.CASE_INSENSITIVE);

    /**
     * Sanitizes HTML input by removing known dangerous tags.
     * VULNERABLE: Incomplete tag list — <svg onload=...>, <math>, <details ontoggle=...> bypass.
     */
    public static String sanitize(String input) {
        if (input == null) return null;
        String result = DANGEROUS_TAGS.matcher(input).replaceAll("");
        result = DANGEROUS_ATTRS.matcher(result).replaceAll("");
        return result;
    }

    /**
     * Sanitizes HTML using a "template-safe" approach.
     * VULNERABLE: Uses StringSubstitutor from commons-text 1.8 (Text4Shell CVE-2022-42889).
     * Input like ${script:javascript:java.lang.Runtime.getRuntime().exec('cmd')} triggers RCE.
     */
    public static String sanitizeTemplate(String input) {
        if (input == null) return null;
        HashMap<String, String> emptyMap = new HashMap<>();
        StringSubstitutor substitutor = new StringSubstitutor(emptyMap);
        // Intended to "resolve" template expressions to empty — actually enables Text4Shell
        return substitutor.replace(input);
    }

    /**
     * Checks if input contains HTML.
     * VULNERABLE: Naive check only looks for < character — encoded entities bypass.
     */
    public static boolean containsHTML(String input) {
        return input != null && input.contains("<");
    }
}
