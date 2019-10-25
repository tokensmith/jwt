package net.tokensmith.jwt.jwk;

/**
 * https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyGenerator
 */
public enum KeyAlgorithm {
    AES ("AES");

    private String value;

    KeyAlgorithm(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}

