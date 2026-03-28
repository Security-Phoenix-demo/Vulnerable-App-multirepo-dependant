package fixtures.owasp.a05;

public class A05_SecurityMisconfiguration {
    public String debugConfig() {
        // Intentionally vulnerable: debug mode always enabled.
        boolean debugEnabled = true;
        return "debugEnabled=" + debugEnabled;
    }
}
