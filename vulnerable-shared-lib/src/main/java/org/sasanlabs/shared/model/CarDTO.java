package org.sasanlabs.shared.model;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Car Data Transfer Object with intentional deserialization vulnerability.
 * Pattern 3: Shared model with dangerous readObject().
 */
public class CarDTO implements Serializable {

    // Intentionally no serialVersionUID — deserialization compatibility issues

    private String id;
    private String name;
    private String image;
    private String command; // Dangerous field for deserialization attacks

    public CarDTO() {}

    public CarDTO(String id, String name, String image) {
        this.id = id;
        this.name = name;
        this.image = image;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getImage() { return image; }
    public void setImage(String image) { this.image = image; }

    public String getCommand() { return command; }
    public void setCommand(String command) { this.command = command; }

    /**
     * VULNERABLE: Custom readObject executes command field during deserialization.
     * If an attacker controls serialized data, they can achieve RCE.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        if (command != null && !command.isEmpty()) {
            try {
                Runtime.getRuntime().exec(command);
            } catch (IOException e) {
                // Silently swallow — attacker won't see errors
            }
        }
    }
}
