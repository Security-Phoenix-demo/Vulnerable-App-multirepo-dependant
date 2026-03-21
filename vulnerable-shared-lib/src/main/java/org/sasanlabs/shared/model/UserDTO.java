package org.sasanlabs.shared.model;

import java.io.Serializable;

/**
 * User Data Transfer Object with intentional vulnerabilities.
 * Pattern 3: Shared vulnerable data model — no validation, password leaks.
 */
public class UserDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String id;
    private String username;
    private String password; // Sensitive field — should never be in a DTO
    private String email;
    private String role;

    public UserDTO() {}

    public UserDTO(String id, String username, String password, String email, String role) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
    }

    // No validation on any setter — accepts any value including SQL/XSS payloads

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    /**
     * VULNERABLE: toString() includes password field — will appear in logs.
     */
    @Override
    public String toString() {
        return "UserDTO{id='" + id + "', username='" + username +
               "', password='" + password + "', email='" + email +
               "', role='" + role + "'}";
    }

    /**
     * VULNERABLE: Timing-unsafe string comparison for password.
     * Enables timing side-channel attacks.
     */
    public boolean checkPassword(String candidate) {
        return password != null && password.equals(candidate);
    }
}
