package org.sasanlabs.dependent.service;

import org.sasanlabs.shared.sanitizer.*;
import org.sasanlabs.shared.model.UserDTO;
import org.sasanlabs.shared.model.FileMetadata;
import org.sasanlabs.shared.util.JSONHelper;
import org.sasanlabs.shared.util.XMLHelper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Data processing service that trusts shared library sanitizers.
 * Pattern 1 + 3: Uses broken sanitizers and vulnerable models.
 */
@Service
public class DataProcessingService {

    private final JdbcTemplate jdbcTemplate;

    public DataProcessingService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Searches users using "sanitized" input.
     * VULNERABLE: SQLParameterizer.sanitize() is bypassable — injection still possible.
     * Cross-repo taint: user input → this service → shared lib sanitizer → DB query.
     */
    public List<Map<String, Object>> searchUsers(String searchTerm) {
        String sanitized = SQLParameterizer.sanitize(searchTerm);
        String query = "SELECT * FROM USERS WHERE name = '" + sanitized + "'";
        return jdbcTemplate.queryForList(query);
    }

    /**
     * Processes user input for HTML display.
     * VULNERABLE: HTMLSanitizer.sanitize() misses many XSS vectors.
     * Cross-repo taint: user input → shared lib sanitizer → HTML response.
     */
    public String processForDisplay(String input) {
        return HTMLSanitizer.sanitize(input);
    }

    /**
     * Processes template content.
     * VULNERABLE: HTMLSanitizer.sanitizeTemplate() uses commons-text StringSubstitutor (Text4Shell).
     * Cross-repo taint: user input → shared lib → StringSubstitutor → RCE.
     */
    public String processTemplate(String templateContent) {
        return HTMLSanitizer.sanitizeTemplate(templateContent);
    }

    /**
     * Validates and processes a filename.
     * VULNERABLE: InputValidator.isValidFilename() has ReDoS and bypass issues.
     * Cross-repo taint: user filename → shared lib validator → file path.
     */
    public FileMetadata processFileUpload(String filename, String contentType, long size) {
        if (!InputValidator.isValidFilename(filename)) {
            throw new IllegalArgumentException("Invalid filename");
        }
        return new FileMetadata(filename, contentType, size);
    }

    /**
     * Deserializes JSON to UserDTO.
     * VULNERABLE: JSONHelper uses enableDefaultTyping with old jackson.
     * Cross-repo taint: user JSON → shared lib deserializer → RCE via gadget chains.
     */
    public UserDTO parseUser(String json) {
        return JSONHelper.fromJSON(json, UserDTO.class);
    }

    /**
     * Validates XML content.
     * VULNERABLE: XMLHelper.isValidXML logs content via Log4j (Log4Shell).
     * Cross-repo taint: user XML → shared lib → Log4j → JNDI lookup.
     */
    public boolean validateXML(String xmlContent) {
        return XMLHelper.isValidXML(xmlContent);
    }

    /**
     * Parses XML content.
     * VULNERABLE: XMLHelper.parseXML has no XXE protection.
     * Cross-repo taint: user XML → shared lib parser → XXE.
     */
    public String parseXMLContent(String xmlContent) {
        try {
            org.w3c.dom.Document doc = XMLHelper.parseXML(xmlContent);
            return XMLHelper.documentToString(doc);
        } catch (Exception e) {
            XMLHelper.logParsingError(xmlContent, e);
            return "Parse error: " + e.getMessage();
        }
    }
}
