package fixtures.owasp.a10;

import java.net.URL;

public class A10_SSRF {
    public URL fetchUrl(String url) throws Exception {
        // Intentionally vulnerable: no allowlist / metadata endpoint protections.
        return new URL(url);
    }
}
