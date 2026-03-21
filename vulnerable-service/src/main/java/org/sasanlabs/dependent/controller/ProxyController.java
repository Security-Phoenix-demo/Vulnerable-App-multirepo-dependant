package org.sasanlabs.dependent.controller;

import org.sasanlabs.dependent.service.VulnerableAppClient;
import org.sasanlabs.shared.sanitizer.CommandSanitizer;
import org.sasanlabs.shared.sanitizer.URLValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Proxy controller that relays requests to VulnerableApp.
 * Pattern 2: Microservice taint relay — user input forwarded across service boundary.
 */
@RestController
@RequestMapping("/api/proxy")
public class ProxyController {

    private final VulnerableAppClient client;

    public ProxyController(VulnerableAppClient client) {
        this.client = client;
    }

    /**
     * Forwards arbitrary requests to VulnerableApp.
     * VULNERABLE: User-controlled path is passed directly to backend — open proxy.
     * Cross-repo taint: user input → this controller → HTTP → VulnerableApp → any vulnerability.
     */
    @GetMapping("/forward")
    public ResponseEntity<String> forward(@RequestParam String path) {
        String result = client.get(path);
        return ResponseEntity.ok(result);
    }

    /**
     * Proxy for SSRF — "validates" URL then forwards.
     * VULNERABLE: URLValidator.isAllowed() doesn't resolve DNS.
     * Cross-repo taint: user URL → shared lib validator (bypass) → VulnerableApp SSRF.
     */
    @GetMapping("/fetch")
    public ResponseEntity<String> fetch(@RequestParam String url) {
        if (!URLValidator.isAllowed(url)) {
            return ResponseEntity.badRequest().body("URL not allowed");
        }
        String result = client.fetchUrl(url, "LEVEL_1");
        return ResponseEntity.ok(result);
    }

    /**
     * Proxy for ping — "sanitizes" input then forwards.
     * VULNERABLE: CommandSanitizer.sanitize() misses newlines and subshells.
     * Cross-repo taint: user input → shared lib sanitizer → VulnerableApp command injection.
     */
    @GetMapping("/ping")
    public ResponseEntity<String> ping(@RequestParam String target) {
        String sanitized = CommandSanitizer.sanitize(target);
        String result = client.ping(sanitized, "LEVEL_1");
        return ResponseEntity.ok(result);
    }

    /**
     * Proxy for SQL query — "validates" then forwards.
     * VULNERABLE: Forwards user-controlled ID to SQL injection endpoint.
     * Cross-repo taint: user input → this controller → VulnerableApp SQLi endpoint.
     */
    @GetMapping("/car")
    public ResponseEntity<String> getCar(@RequestParam String id,
                                          @RequestParam(defaultValue = "LEVEL_1") String level) {
        String result = client.queryCar(id, level);
        return ResponseEntity.ok(result);
    }
}
