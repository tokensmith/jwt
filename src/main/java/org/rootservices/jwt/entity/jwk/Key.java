package org.rootservices.jwt.entity.jwk;

import java.util.Base64;

/**
 * Created by tommackenzie on 8/19/15.
 *
 * JSON Web Key, https://tools.ietf.org/html/rfc7517
 */
public class Key {
    private KeyType keyType;

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }
}
