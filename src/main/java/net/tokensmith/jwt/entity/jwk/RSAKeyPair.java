package net.tokensmith.jwt.entity.jwk;

import java.math.BigInteger;
import java.util.Optional;

/**
 * Created by tommackenzie on 11/4/15.
 *
 * All string values are,
 * "base64url encoding of their big-endian representations"
 * per, https://tools.ietf.org/html/rfc7517#appendix-A.1
 *
 * for explanation of variables see,
 * https://www.ietf.org/rfc/rfc2437.txt sections 3.1 and 3.2
 *
 */
public class RSAKeyPair extends Key {

    private BigInteger n; // modulus
    private BigInteger e; // public exponent
    private BigInteger d; // private exponent
    private BigInteger p;
    private BigInteger q;
    private BigInteger dp;
    private BigInteger dq;
    private BigInteger qi;

    public RSAKeyPair(Optional<String> keyId, KeyType keyType, Use use, BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, BigInteger dp, BigInteger dq, BigInteger qi) {
        super(keyId, keyType, use);
        this.n = n;
        this.e = e;
        this.d = d;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qi = qi;
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

    public BigInteger getD() {
        return d;
    }

    public void setD(BigInteger d) {
        this.d = d;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(BigInteger q) {
        this.q = q;
    }

    public BigInteger getDp() {
        return dp;
    }

    public void setDp(BigInteger dp) {
        this.dp = dp;
    }

    public BigInteger getDq() {
        return dq;
    }

    public void setDq(BigInteger dq) {
        this.dq = dq;
    }

    public BigInteger getQi() {
        return qi;
    }

    public void setQi(BigInteger qi) {
        this.qi = qi;
    }
}
