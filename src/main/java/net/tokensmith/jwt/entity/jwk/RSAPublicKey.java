package net.tokensmith.jwt.entity.jwk;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Created by tommackenzie on 11/6/15.
 */
public class RSAPublicKey extends Key {
    private BigInteger n; // modulus
    private BigInteger e; // public exponent

    public RSAPublicKey(Optional<String> keyId, Use use, BigInteger n, BigInteger e) {
        super(keyId, KeyType.RSA, use);
        this.n = n;
        this.e = e;
    }

    public BigInteger getN() {
        return n;
    }

    public void setN(BigInteger n) {
        this.n = n;
    }

    public BigInteger getE() {
        return e;
    }

    public void setE(BigInteger e) {
        this.e = e;
    }

    public static class Builder {
        protected Optional<String> keyId = Optional.empty();
        private Use use;
        private BigInteger n; // modulus
        private BigInteger e; // public exponent

        public Builder keyId(Optional<String> keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder use(Use use) {
            this.use = use;
            return this;
        }

        public Builder n(BigInteger n) {
            this.n = n;
            return this;
        }

        public Builder e(BigInteger e) {
            this.e = e;
            return this;
        }

        public RSAPublicKey build() {
            return new RSAPublicKey(keyId, use, n, e);
        }
    }
}
