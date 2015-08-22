package org.rootservices.jwt.entity.jwk;

import java.util.Base64;

/**
 * Created by tommackenzie on 8/19/15.
 *
 * JSON Web Key, https://tools.ietf.org/html/rfc7517
 */
public class Key {
    private KeyType keyType;
    private String key;

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
