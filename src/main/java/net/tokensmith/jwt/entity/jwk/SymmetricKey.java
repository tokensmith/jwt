package net.tokensmith.jwt.entity.jwk;

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
