package fixtures.owasp.a09;

public class A09_SecurityLoggingAndMonitoringFailures {
    public void handleFailedLogin(String username) {
        // Intentionally vulnerable: no security event logging.
        if (username == null) {
            return;
        }
    }
}
