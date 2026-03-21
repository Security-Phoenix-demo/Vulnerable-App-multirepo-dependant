package org.sasanlabs.shared.config;

/**
 * Shared Database Configuration with hardcoded credentials.
 * Pattern 4: Configuration/secrets leakage across repos.
 */
public class SharedDatabaseConfig {

    // VULNERABLE: Hardcoded database credentials
    public static final String DB_URL = "jdbc:h2:mem:testdb";
    public static final String DB_DRIVER = "org.h2.Driver";

    public static final String ADMIN_USER = "admin";
    public static final String ADMIN_PASSWORD = "hacker";

    public static final String APP_USER = "application";
    public static final String APP_PASSWORD = "hacker";

    // VULNERABLE: Overly permissive H2 settings
    public static final boolean H2_CONSOLE_ENABLED = true;
    public static final String H2_CONSOLE_PATH = "/h2-console";

    /**
     * VULNERABLE: Returns JDBC URL with embedded credentials.
     */
    public static String getAdminJdbcUrl() {
        return DB_URL + ";USER=" + ADMIN_USER + ";PASSWORD=" + ADMIN_PASSWORD;
    }

    /**
     * VULNERABLE: Returns connection string suitable for display/logging
     * that includes the password.
     */
    public static String getConnectionInfo() {
        return "Database: " + DB_URL + " User: " + ADMIN_USER + " Password: " + ADMIN_PASSWORD;
    }
}
