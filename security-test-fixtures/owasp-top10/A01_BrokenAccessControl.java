package fixtures.owasp.a01;

public class A01_BrokenAccessControl {
    public String getAdminReport(String userRole) {
        // Intentionally vulnerable: missing authorization check.
        return "Full admin report with sensitive data";
    }
}
