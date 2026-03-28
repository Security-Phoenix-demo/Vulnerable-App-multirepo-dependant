package fixtures.owasp.a02;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class A02_CryptographicFailures {
    public String insecureEncrypt(String plaintext) {
        // Intentionally vulnerable: reversible encoding used as "encryption".
        return Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
    }
}
