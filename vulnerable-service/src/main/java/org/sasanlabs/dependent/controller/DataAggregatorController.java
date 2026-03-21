package org.sasanlabs.dependent.controller;

import org.sasanlabs.dependent.service.VulnerableAppClient;
import org.sasanlabs.dependent.service.DataProcessingService;
import org.sasanlabs.shared.sanitizer.HTMLSanitizer;
import org.sasanlabs.shared.util.JSONHelper;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Aggregates data from VulnerableApp and processes it.
 * Pattern 2 + 1: Fetches from backend, processes with broken sanitizers.
 */
@RestController
@RequestMapping("/api/aggregate")
public class DataAggregatorController {

    private final VulnerableAppClient client;
    private final DataProcessingService processingService;

    public DataAggregatorController(VulnerableAppClient client,
                                     DataProcessingService processingService) {
        this.client = client;
        this.processingService = processingService;
    }

    /**
     * Fetches persistent XSS comments from VulnerableApp and renders them.
     * VULNERABLE: Reverse taint — stored XSS in VulnerableApp rendered here unsafely.
     * Cross-repo taint: VulnerableApp DB → HTTP response → this service → HTML output.
     */
    @GetMapping(value = "/comments", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> getComments(
            @RequestParam(defaultValue = "LEVEL_1") String level) {
        String rawComments = client.getComments(level);
        // "Sanitize" before display — but HTMLSanitizer is broken
        String sanitized = HTMLSanitizer.sanitize(rawComments);
        String html = "<html><body><h2>Comments from Backend</h2><div>" +
                       sanitized + "</div></body></html>";
        return ResponseEntity.ok(html);
    }

    /**
     * Fetches car data and re-serializes it.
     * VULNERABLE: Deserializes JSON from VulnerableApp using JSONHelper (enableDefaultTyping).
     * Cross-repo taint: VulnerableApp response → JSONHelper.fromJSON → potential RCE.
     */
    @GetMapping("/car")
    public ResponseEntity<String> getCar(@RequestParam String id) {
        String rawResponse = client.queryCar(id, "LEVEL_1");
        // Re-process through our vulnerable JSON helper
        Object parsed = JSONHelper.fromJSON(rawResponse, Object.class);
        String prettyResult = JSONHelper.prettyPrint(parsed);
        return ResponseEntity.ok(prettyResult);
    }

    /**
     * Accepts user HTML content and processes it.
     * VULNERABLE: Uses broken HTMLSanitizer then returns in HTML response.
     * Cross-repo taint: user input → shared lib sanitizer → HTML response (XSS).
     */
    @PostMapping(value = "/render", consumes = MediaType.TEXT_PLAIN_VALUE,
                 produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> renderContent(@RequestBody String content) {
        String processed = processingService.processForDisplay(content);
        String html = "<html><body><div class='user-content'>" +
                       processed + "</div></body></html>";
        return ResponseEntity.ok(html);
    }

    /**
     * Processes template content.
     * VULNERABLE: Uses HTMLSanitizer.sanitizeTemplate() — Text4Shell via commons-text.
     * Cross-repo taint: user template → shared lib → StringSubstitutor → RCE.
     */
    @PostMapping(value = "/template", consumes = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> processTemplate(@RequestBody String template) {
        String result = processingService.processTemplate(template);
        return ResponseEntity.ok(result);
    }

    /**
     * Accepts and validates XML content.
     * VULNERABLE: XMLHelper has XXE + Log4Shell issues.
     * Cross-repo taint: user XML → shared lib parser → XXE / Log4Shell.
     */
    @PostMapping(value = "/xml", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<String> processXML(@RequestBody String xml) {
        String result = processingService.parseXMLContent(xml);
        return ResponseEntity.ok(result);
    }
}
