package org.rootservices.jwt.entity.jwk;

/**
 * Created by tommackenzie on 11/6/15.
 */
public class RSAPublicKey extends Key {
    private Use use;
    private String n; // modulus
    private String e; // public exponent

    public RSAPublicKey(KeyType keyType, Use use, String n, String e) {
        super(keyType);
        this.use = use;
        this.n = n;
        this.e = e;
    }

    public Use getUse() {
        return use;
    }

    public void setUse(Use use) {
        this.use = use;
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
