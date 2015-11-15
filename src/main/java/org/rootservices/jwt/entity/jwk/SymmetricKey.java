package org.rootservices.jwt.entity.jwk;

/**
 * Created by tommackenzie on 11/4/15.
 */
public class SymmetricKey extends Key {
    private String key;

    public SymmetricKey() {}

    public SymmetricKey(KeyType keyType, String key) {
        super(keyType);
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
