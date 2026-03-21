package org.sasanlabs.dependent.controller;

import org.sasanlabs.dependent.service.DataProcessingService;
import org.sasanlabs.dependent.service.CryptoService;
import org.sasanlabs.shared.model.UserDTO;
import org.sasanlabs.shared.util.JSONHelper;
import org.sasanlabs.shared.config.SharedDatabaseConfig;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * User management controller using shared vulnerable models and config.
 * Pattern 3 + 4: Shared models with no validation, hardcoded credentials.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final JdbcTemplate jdbcTemplate;
    private final DataProcessingService processingService;
    private final CryptoService cryptoService;

    public UserController(JdbcTemplate jdbcTemplate,
                          DataProcessingService processingService,
                          CryptoService cryptoService) {
        this.jdbcTemplate = jdbcTemplate;
        this.processingService = processingService;
        this.cryptoService = cryptoService;
    }

    /**
     * Creates a user from JSON body.
     * VULNERABLE: No input validation on UserDTO (Pattern 3).
     * VULNERABLE: JSONHelper.fromJSON uses enableDefaultTyping (Pattern 5).
     * VULNERABLE: Password stored with MD5 hash (Pattern 4).
     * Cross-repo taint: user JSON → shared lib deserializer → shared model → DB.
     */
    @PostMapping
    public ResponseEntity<String> createUser(@RequestBody String userJson) {
        UserDTO user = JSONHelper.fromJSON(userJson, UserDTO.class);

        // Hash password with weak MD5 from shared config
        String hashedPassword = cryptoService.hashPassword(user.getPassword());

        // VULNERABLE: String concatenation SQL with user-controlled values
        String query = "INSERT INTO USERS (name, password, email) VALUES ('" +
                       user.getUsername() + "', '" + hashedPassword + "', '" +
                       user.getEmail() + "')";
        jdbcTemplate.execute(query);

        // VULNERABLE: toString() includes password in response
        return ResponseEntity.ok("Created: " + user.toString());
    }

    /**
     * Searches users by name.
     * VULNERABLE: Uses broken SQLParameterizer from shared library.
     * Cross-repo taint: user input → shared lib sanitizer → SQL query.
     */
    @GetMapping("/search")
    public ResponseEntity<String> searchUsers(@RequestParam String name) {
        List<Map<String, Object>> results = processingService.searchUsers(name);
        return ResponseEntity.ok(JSONHelper.prettyPrint(results));
    }

    /**
     * Gets database connection info.
     * VULNERABLE: Exposes hardcoded credentials from SharedDatabaseConfig.
     * Pattern 4: Config leakage.
     */
    @GetMapping("/dbinfo")
    public ResponseEntity<String> getDatabaseInfo() {
        return ResponseEntity.ok(SharedDatabaseConfig.getConnectionInfo());
    }

    /**
     * Encrypts user data.
     * VULNERABLE: Uses DES/ECB/hardcoded key from shared config.
     * Pattern 4: Weak crypto.
     */
    @PostMapping("/encrypt")
    public ResponseEntity<String> encryptData(@RequestBody String data) {
        String encrypted = cryptoService.encrypt(data);
        return ResponseEntity.ok(encrypted);
    }
}
