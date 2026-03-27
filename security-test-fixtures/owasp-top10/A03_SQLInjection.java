package fixtures.owasp.a03;

public class A03_SQLInjection {
    public String buildQuery(String username) {
        // Intentionally vulnerable: string concatenation with untrusted input.
        return "SELECT * FROM users WHERE username = '" + username + "'";
    }
}
