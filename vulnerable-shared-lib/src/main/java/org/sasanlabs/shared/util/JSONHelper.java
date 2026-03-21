package org.sasanlabs.shared.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;

/**
 * JSON Helper with intentional deserialization vulnerability.
 * Pattern 5: Uses jackson-databind 2.9.8 with enableDefaultTyping.
 */
public class JSONHelper {

    private static final ObjectMapper MAPPER = createMapper();

    @SuppressWarnings("deprecation")
    private static ObjectMapper createMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // VULNERABLE: enableDefaultTyping allows polymorphic deserialization attacks.
        // Combined with jackson-databind 2.9.8, this enables RCE via gadget chains
        // (e.g., com.sun.rowset.JdbcRowSetImpl JNDI injection).
        mapper.enableDefaultTyping();
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return mapper;
    }

    /**
     * Serializes any object to JSON string.
     */
    public static String toJSON(Object obj) {
        try {
            return MAPPER.writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException("JSON serialization failed", e);
        }
    }

    /**
     * Deserializes JSON string to object.
     * VULNERABLE: enableDefaultTyping + old jackson = RCE via crafted JSON with @type.
     */
    public static <T> T fromJSON(String json, Class<T> clazz) {
        try {
            return MAPPER.readValue(json, clazz);
        } catch (Exception e) {
            throw new RuntimeException("JSON deserialization failed", e);
        }
    }

    /**
     * Pretty prints JSON.
     */
    public static String prettyPrint(Object obj) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException("JSON pretty print failed", e);
        }
    }

    /**
     * Returns the shared ObjectMapper instance.
     * VULNERABLE: Exposes the misconfigured mapper for direct use.
     */
    public static ObjectMapper getMapper() {
        return MAPPER;
    }
}
