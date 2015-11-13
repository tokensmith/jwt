package org.rootservices.jwt.entity.jwk;

/**
 * Created by tommackenzie on 11/4/15.
 *
 * All string values are,
 * "base64url encoding of their big-endian representations"
 * per, https://tools.ietf.org/html/rfc7517#appendix-A.1
 *
 * for explanation of variables see,
 * https://www.ietf.org/rfc/rfc2437.txt sections 3.1 & 3.2
 *
 */
public class RSAKeyPair extends Key {
    private Use use;
    private String n; // modulus
    private String e; // public exponent
    private String d; // private exponent
    private String p;
    private String q;
    private String dp;
    private String dq;
    private String qi;

    public RSAKeyPair(Use use, String n, String e, String d, String p, String q, String dp, String dq, String qi) {
        this.use = use;
        this.n = n;
        this.e = e;
        this.d = d;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qi = qi;
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

    public String getD() {
        return d;
    }

    public void setD(String d) {
        this.d = d;
    }

    public String getP() {
        return p;
    }

    public void setP(String p) {
        this.p = p;
    }

    public String getQ() {
        return q;
    }

    public void setQ(String q) {
        this.q = q;
    }

    public String getDp() {
        return dp;
    }

    public void setDp(String dp) {
        this.dp = dp;
    }

    public String getDq() {
        return dq;
    }

    public void setDq(String dq) {
        this.dq = dq;
    }

    public String getQi() {
        return qi;
    }

    public void setQi(String qi) {
        this.qi = qi;
    }
}
