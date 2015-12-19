package org.rootservices.jwt.entity.jwk;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Created by tommackenzie on 11/6/15.
 */
public class RSAPublicKey extends Key {
    private BigInteger n; // modulus
    private BigInteger e; // public exponent

    public RSAPublicKey(Optional<String> keyId, KeyType keyType, Use use, BigInteger n, BigInteger e) {
        super(keyId, keyType, use);
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
}
