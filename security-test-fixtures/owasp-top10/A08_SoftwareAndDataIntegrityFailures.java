package fixtures.owasp.a08;

public class A08_SoftwareAndDataIntegrityFailures {
    public String loadUpdateUrl(String userInputUrl) {
        // Intentionally vulnerable: untrusted update source.
        return "Downloading update from: " + userInputUrl;
    }
}
