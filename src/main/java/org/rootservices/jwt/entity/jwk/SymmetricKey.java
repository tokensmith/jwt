package org.rootservices.jwt.entity.jwk;

import java.util.Optional;

/**
 * Created by tommackenzie on 11/4/15.
 */
public class SymmetricKey extends Key {
    private String key;

    public SymmetricKey(Optional<String> keyId, String key, Use use) {
        super(keyId, KeyType.OCT, use);
        this.key = key;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
