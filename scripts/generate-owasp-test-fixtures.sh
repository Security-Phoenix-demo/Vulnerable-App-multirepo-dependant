#!/usr/bin/env bash
set -euo pipefail

# Testing-only insecure fixtures for OWASP Top 10 validation.
# Default mode is DRY-RUN. Use --apply to write files.

MODE="dry-run"
if [[ "${1:-}" == "--apply" ]]; then
  MODE="apply"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="$ROOT_DIR/security-test-fixtures/owasp-top10"

write_file() {
  local rel_path="$1"
  local abs_path="$FIXTURE_DIR/$rel_path"

  if [[ "$MODE" == "dry-run" ]]; then
    echo "[DRY-RUN] would create: $abs_path"
    return
  fi

  mkdir -p "$(dirname "$abs_path")"
  cat >"$abs_path"
  echo "[APPLY] created: $abs_path"
}

write_file "README.md" <<'EOF'
# OWASP Top 10 Vulnerable Fixtures (Testing Only)

These files are intentionally insecure and exist only to test static/dynamic security tooling.
Do not deploy, copy, or reuse in production systems.
EOF

write_file "A01_BrokenAccessControl.java" <<'EOF'
package fixtures.owasp.a01;

public class A01_BrokenAccessControl {
    public String getAdminReport(String userRole) {
        // Intentionally vulnerable: missing authorization check.
        return "Full admin report with sensitive data";
    }
}
EOF

write_file "A02_CryptographicFailures.java" <<'EOF'
package fixtures.owasp.a02;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class A02_CryptographicFailures {
    public String insecureEncrypt(String plaintext) {
        // Intentionally vulnerable: reversible encoding used as "encryption".
        return Base64.getEncoder().encodeToString(plaintext.getBytes(StandardCharsets.UTF_8));
    }
}
EOF

write_file "A03_SQLInjection.java" <<'EOF'
package fixtures.owasp.a03;

public class A03_SQLInjection {
    public String buildQuery(String username) {
        // Intentionally vulnerable: string concatenation with untrusted input.
        return "SELECT * FROM users WHERE username = '" + username + "'";
    }
}
EOF

write_file "A04_InsecureDesign.java" <<'EOF'
package fixtures.owasp.a04;

public class A04_InsecureDesign {
    public boolean allowMoneyTransfer(String accountId, double amount) {
        // Intentionally vulnerable: no limits, no anti-abuse controls, no fraud checks.
        return amount > 0;
    }
}
EOF

write_file "A05_SecurityMisconfiguration.java" <<'EOF'
package fixtures.owasp.a05;

public class A05_SecurityMisconfiguration {
    public String debugConfig() {
        // Intentionally vulnerable: debug mode always enabled.
        boolean debugEnabled = true;
        return "debugEnabled=" + debugEnabled;
    }
}
EOF

write_file "A06_VulnerableAndOutdatedComponents.txt" <<'EOF'
INTENTIONALLY INSECURE EXAMPLE

Component: old-library
Version: 1.0.0
Known issue: hypothetical remote code execution

Purpose: test dependency scanners and policy gates.
EOF

write_file "A07_IdentificationAndAuthFailures.java" <<'EOF'
package fixtures.owasp.a07;

public class A07_IdentificationAndAuthFailures {
    public boolean login(String username, String password) {
        // Intentionally vulnerable: hardcoded default credentials.
        return "admin".equals(username) && "admin".equals(password);
    }
}
EOF

write_file "A08_SoftwareAndDataIntegrityFailures.java" <<'EOF'
package fixtures.owasp.a08;

public class A08_SoftwareAndDataIntegrityFailures {
    public String loadUpdateUrl(String userInputUrl) {
        // Intentionally vulnerable: untrusted update source.
        return "Downloading update from: " + userInputUrl;
    }
}
EOF

write_file "A09_SecurityLoggingAndMonitoringFailures.java" <<'EOF'
package fixtures.owasp.a09;

public class A09_SecurityLoggingAndMonitoringFailures {
    public void handleFailedLogin(String username) {
        // Intentionally vulnerable: no security event logging.
        if (username == null) {
            return;
        }
    }
}
EOF

write_file "A10_SSRF.java" <<'EOF'
package fixtures.owasp.a10;

import java.net.URL;

public class A10_SSRF {
    public URL fetchUrl(String url) throws Exception {
        // Intentionally vulnerable: no allowlist / metadata endpoint protections.
        return new URL(url);
    }
}
EOF

echo "Done. Mode: $MODE"
