package org.rootservices.jwt.entity.jwk;

import java.util.Optional;

/**
 * Created by tommackenzie on 8/19/15.
 *
 * JSON Web Key, https://tools.ietf.org/html/rfc7517
 */
public class Key {
    protected Optional<String> keyId;
    protected KeyType keyType;
    private Use use;

    public Key() {}

    public Key(Optional<String> keyId, KeyType keyType, Use use) {
        this.keyId = keyId;
        this.keyType = keyType;
        this.use = use;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    public Optional<String> getKeyId() {
        return keyId;
    }

    public void setKeyId(Optional<String> keyId) {
        this.keyId = keyId;
    }

    public Use getUse() {
        return use;
    }

    public void setUse(Use use) {
        this.use = use;
    }
}
