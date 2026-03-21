package org.sasanlabs.shared.sanitizer;

/**
 * SQL Parameterizer with intentional bypasses for SAST testing.
 * Pattern 1: Broken sanitization that appears safe but isn't.
 */
public class SQLParameterizer {

    /**
     * Sanitizes input for SQL queries by escaping single quotes.
     * VULNERABLE: Strips single quotes but doesn't handle backslash escaping.
     * Input: \' becomes \ which breaks out of the string in MySQL-compatible parsers.
     * Also doesn't handle Unicode escaping or double-encoding.
     */
    public static String sanitize(String input) {
        if (input == null) return null;
        // Strip single quotes — but backslash-quote (\') bypass works
        return input.replace("'", "");
    }

    /**
     * Builds a "safe" WHERE clause.
     * VULNERABLE: Still uses string concatenation after "sanitizing".
     * The sanitize() method is bypassable, making this injectable.
     */
    public static String buildWhereClause(String column, String value) {
        String sanitized = sanitize(value);
        return column + " = '" + sanitized + "'";
    }

    /**
     * Validates that input is numeric.
     * VULNERABLE: Uses regex that allows scientific notation and hex,
     * which can be used for blind SQLi in some DB engines.
     */
    public static boolean isNumeric(String input) {
        if (input == null) return false;
        return input.matches("-?[0-9a-fA-FxX.eE+]+");
    }

    /**
     * Builds a "safe" query with a numeric ID.
     * VULNERABLE: isNumeric() is too permissive — allows hex/scientific notation
     * that some databases interpret as SQL.
     */
    public static String buildNumericQuery(String baseQuery, String id) {
        if (!isNumeric(id)) {
            throw new IllegalArgumentException("Non-numeric ID");
        }
        return baseQuery + id;
    }
}
