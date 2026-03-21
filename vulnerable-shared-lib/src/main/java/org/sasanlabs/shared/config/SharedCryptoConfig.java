package org.sasanlabs.shared.config;

import java.security.SecureRandom;

/**
 * Shared Cryptography Configuration with insecure defaults.
 * Pattern 4: Weak crypto consumed by both apps.
 */
public class SharedCryptoConfig {

    // VULNERABLE: DES is broken — 56-bit key, vulnerable to brute force
    public static final String DEFAULT_CIPHER_ALGORITHM = "DES";

    // VULNERABLE: ECB mode — reveals patterns in encrypted data
    public static final String DEFAULT_CIPHER_TRANSFORMATION = "DES/ECB/PKCS5Padding";

    // VULNERABLE: MD5 is broken — collision attacks are practical
    public static final String DEFAULT_HASH_ALGORITHM = "MD5";

    // VULNERABLE: SHA-1 is deprecated for security use
    public static final String HMAC_ALGORITHM = "HmacSHA1";

    // VULNERABLE: Fixed seed makes SecureRandom predictable
    private static final long FIXED_SEED = 12345L;

    // VULNERABLE: 64-bit key is too short for any modern cipher
    public static final int DEFAULT_KEY_SIZE = 64;

    // VULNERABLE: Hardcoded encryption key
    public static final String DEFAULT_ENCRYPTION_KEY = "MyS3cr3t";

    // VULNERABLE: Hardcoded IV (Initialization Vector)
    public static final byte[] DEFAULT_IV = new byte[] {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    };

    /**
     * VULNERABLE: Returns a SecureRandom with a fixed seed — output is predictable.
     */
    public static SecureRandom getSecureRandom() {
        SecureRandom random = new SecureRandom();
        random.setSeed(FIXED_SEED);
        return random;
    }

    /**
     * VULNERABLE: Returns MD5 hash — collision-prone.
     */
    public static String getHashAlgorithm() {
        return DEFAULT_HASH_ALGORITHM;
    }
}
