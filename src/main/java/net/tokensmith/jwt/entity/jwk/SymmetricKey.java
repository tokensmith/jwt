package net.tokensmith.jwt.entity.jwk;

import java.util.Optional;

/**
 * Represents a symmetric key.
 */
public class SymmetricKey extends Key {
    private String key;

    /**
     * Construct a Symmetric Key.
     *
     * @param keyId the id of the key
     * @param key the base64, url encoded, without padding symmetric key value
     * @param use how the key will be used, sign, encrypt.
     */
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

    public static class Builder {
        protected Optional<String> keyId = Optional.empty();
        private Use use;
        private String key;

        public Builder keyId(Optional<String> keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder use(Use use) {
            this.use = use;
            return this;
        }

        public Builder key(String key) {
            this.key = key;
            return this;
        }

        public SymmetricKey build() {
            return new SymmetricKey(keyId, key, use);
        }
    }
}
