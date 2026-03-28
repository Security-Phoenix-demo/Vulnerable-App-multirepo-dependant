package fixtures.owasp.a07;

public class A07_IdentificationAndAuthFailures {
    public boolean login(String username, String password) {
        // Intentionally vulnerable: hardcoded default credentials.
        return "admin".equals(username) && "admin".equals(password);
    }
}
