package org.rootservices.jwt.entity.jwk;

import java.util.Optional;

/**
 * Created by tommackenzie on 11/6/15.
 */
public class RSAPublicKey extends Key {
    private String n; // modulus
    private String e; // public exponent

    public RSAPublicKey(Optional<String> keyId, KeyType keyType, Use use, String n, String e) {
        super(keyId, keyType, use);
        this.n = n;
        this.e = e;
    }

    public String getN() {
        return n;
    }

    public void setN(String n) {
        this.n = n;
    }

    public String getE() {
        return e;
    }

    public void setE(String e) {
        this.e = e;
    }
}
