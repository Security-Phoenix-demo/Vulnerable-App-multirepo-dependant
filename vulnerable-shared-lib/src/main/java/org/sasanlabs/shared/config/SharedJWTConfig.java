package org.sasanlabs.shared.config;

/**
 * Shared JWT Configuration with weak keys and insecure defaults.
 * Pattern 4: Configuration/secrets leakage.
 */
public class SharedJWTConfig {

    // VULNERABLE: Weak HMAC secret — brute-forceable (only 8 characters)
    public static final String HMAC_SECRET = "s3cr3t!!";

    // VULNERABLE: RSA private key stored as constant in source code
    public static final String RSA_PRIVATE_KEY_PEM =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEpAIBAAKCAQEA2mX3aCbRgWpJ8JJBnJOGRb0rzmKBqRuT3KBbSuFCbdMo+YBb\n" +
            "k85FH3JEwMGbBFPBNFJXqOKJ6NdK1gYBJYcFPOvSCmH0F4VLnLsRbJeg8sgjx7i\n" +
            "Q2FDpgPGKCBnUJKSBXFE9nn1TLEOGJtYGKKhJ/MnvMPJKV4gG98W0CjBiDYMfkR\n" +
            "WkfotXCKBFdXBLGPKOnDFga4gd6K0h0fLQEKaJJMFoOk3ljQKZMqE5JBcFNQg8R9\n" +
            "J5md0cPGNDWjNKWXFHBK0r7wimXBhwME0peTNLFzYzhke5ghCNwVApLIEqHxCv1y\n" +
            "FJ8MpN/vGOPJx28YoEEPKr9b6GCNsgmb7CjVxQIDAQABAoIBAC5RgZ+hBx7xHNaM\n" +
            "pPgwGMnCd2vHoqNzpGJKIzJUBdGvxnCmGnBFBQh5KnHcSBjklBIuz8+FRFp2TLHW\n" +
            "sMuBkYWNxDHdXqOEN4sCBOm8k19MccBfYBJqEynJRMJfK3JCBaJkrVUFakkPTqLN\n" +
            "KEJl1mHxeyEfGpHaFGJEdSFDQVKIDJqEEsx4ByqdRJmA3yfJcX7AFdBFyr2Kwxp0\n" +
            "EBSze4y9eLS2LJPCr3BTCHHJIXHPakPDJRNHfMpZdKfmSNLZCd9VNP0JKKtv3dBD\n" +
            "cC3QoMAYUKhPNFMeC9jNEEt3RpJEzjQHPNBXwx0VgGPb1jQJMQaFzxxHJi1BuZJE\n" +
            "sSmTjCECgYEA8qNGFNOM0e1MlPE0MK0MyYGfdBDBsQKVJpoXJHFWHHSwVgJUNX40\n" +
            "DI4ud7jCI8sCsmPpJkkgnRcsDajr5FQ72JBVXGkPMiB7mYaPBKcm9nLkMFiEB/Sf\n" +
            "oOrRHUBG02mgYCEMbFPznt3emiEvxMPNtDhPOQpmrJhKoi0ppCdME0UCgYEA5MtY\n" +
            "-----END RSA PRIVATE KEY-----";

    // VULNERABLE: RSA public key (paired with the private key above)
    public static final String RSA_PUBLIC_KEY_PEM =
            "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2mX3aCbRgWpJ8JJBnJOG\n" +
            "Rb0rzmKBqRuT3KBbSuFCbdMo+YBbk85FH3JEwMGbBFPBNFJXqOKJ6NdK1gYBJYc\n" +
            "FPOvSCmH0F4VLnLsRbJeg8sgjx7iQ2FDpgPGKCBnUJKSBXFE9nn1TLEOGJtYGKKh\n" +
            "J/MnvMPJKV4gG98W0CjBiDYMfkRWkfotXCKBFdXBLGPKOnDFga4gd6K0h0fLQEKa\n" +
            "JJMFoOk3ljQKZMqE5JBcFNQg8R9J5md0cPGNDWjNKWXFHBK0r7wimXBhwME0peT\n" +
            "NLFzYzhke5ghCNwVApLIEqHxCv1yFJ8MpN/vGOPJx28YoEEPKr9b6GCNsgmb7CjV\n" +
            "xQIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    // VULNERABLE: Algorithm set to "none" is accepted
    public static final boolean ALLOW_NONE_ALGORITHM = true;

    // VULNERABLE: Token expiry set to 365 days
    public static final long TOKEN_EXPIRY_SECONDS = 365 * 24 * 60 * 60;

    // VULNERABLE: No issuer or audience validation
    public static final boolean VALIDATE_ISSUER = false;
    public static final boolean VALIDATE_AUDIENCE = false;
}
