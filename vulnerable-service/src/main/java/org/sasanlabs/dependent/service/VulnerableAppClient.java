package org.sasanlabs.dependent.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * HTTP client for calling VulnerableApp endpoints.
 * Pattern 2: Microservice taint relay — forwards user input to vulnerable backend.
 */
@Service
public class VulnerableAppClient {

    private final RestTemplate restTemplate;

    @Value("${vulnerableapp.base-url}")
    private String baseUrl;

    public VulnerableAppClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * Generic GET request to VulnerableApp.
     * VULNERABLE: Passes user-controlled path/params directly — taint relay.
     */
    public String get(String path) {
        String url = baseUrl + path;
        ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
        return response.getBody();
    }

    /**
     * Generic POST request to VulnerableApp.
     * VULNERABLE: Forwards arbitrary body to VulnerableApp.
     */
    public String post(String path, String body, MediaType contentType) {
        String url = baseUrl + path;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(contentType);
        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
        return response.getBody();
    }

    /**
     * Forwards a file upload to VulnerableApp.
     * VULNERABLE: Passes user-uploaded file directly to backend.
     */
    public String uploadFile(String path, byte[] fileContent, String originalFilename) {
        String url = baseUrl + path;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        ByteArrayResource resource = new ByteArrayResource(fileContent) {
            @Override
            public String getFilename() {
                return originalFilename;
            }
        };
        body.add("file", new HttpEntity<>(resource, headers));

        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(url, requestEntity, String.class);
        return response.getBody();
    }

    /**
     * Fetches SQL injection endpoint with user-supplied ID.
     * VULNERABLE: Direct taint relay of id parameter.
     */
    public String queryCar(String id, String level) {
        return get("/ErrorBasedSQLInjectionVulnerability/" + level + "?id=" + id);
    }

    /**
     * Fetches SSRF endpoint with user-supplied URL.
     * VULNERABLE: Direct taint relay of URL parameter — chained SSRF.
     */
    public String fetchUrl(String fileUrl, String level) {
        return get("/SSRFVulnerability/" + level + "?fileurl=" + fileUrl);
    }

    /**
     * Sends command to command injection endpoint.
     * VULNERABLE: Direct taint relay — chained command injection.
     */
    public String ping(String ipAddress, String level) {
        return get("/CommandInjection/" + level + "?ipaddress=" + ipAddress);
    }

    /**
     * Fetches persistent XSS comments.
     * VULNERABLE: Returns unescaped HTML from VulnerableApp.
     */
    public String getComments(String level) {
        return get("/PersistentXSSInHTMLTagVulnerability/" + level);
    }
}
