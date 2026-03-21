package org.sasanlabs.dependent.service;

import org.sasanlabs.shared.config.SharedCryptoConfig;
import org.sasanlabs.shared.config.SharedJWTConfig;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Crypto service that uses shared library's insecure defaults.
 * Pattern 4: Weak crypto consumed from shared config.
 */
@Service
public class CryptoService {

    /**
     * Encrypts data using shared config defaults.
     * VULNERABLE: Uses DES/ECB with hardcoded key from SharedCryptoConfig.
     */
    public String encrypt(String plaintext) {
        try {
            SecretKeySpec key = new SecretKeySpec(
                    SharedCryptoConfig.DEFAULT_ENCRYPTION_KEY.getBytes(StandardCharsets.UTF_8),
                    SharedCryptoConfig.DEFAULT_CIPHER_ALGORITHM
            );
            Cipher cipher = Cipher.getInstance(SharedCryptoConfig.DEFAULT_CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Decrypts data using shared config defaults.
     * VULNERABLE: Same DES/ECB/hardcoded key issues.
     */
    public String decrypt(String ciphertext) {
        try {
            SecretKeySpec key = new SecretKeySpec(
                    SharedCryptoConfig.DEFAULT_ENCRYPTION_KEY.getBytes(StandardCharsets.UTF_8),
                    SharedCryptoConfig.DEFAULT_CIPHER_ALGORITHM
            );
            Cipher cipher = Cipher.getInstance(SharedCryptoConfig.DEFAULT_CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    /**
     * Hashes a password.
     * VULNERABLE: Uses MD5 from SharedCryptoConfig — collision-prone, no salt.
     */
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance(SharedCryptoConfig.getHashAlgorithm());
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new RuntimeException("Hashing failed", e);
        }
    }

    /**
     * Gets the JWT secret.
     * VULNERABLE: Returns weak hardcoded HMAC secret from SharedJWTConfig.
     */
    public String getJwtSecret() {
        return SharedJWTConfig.HMAC_SECRET;
    }
}
