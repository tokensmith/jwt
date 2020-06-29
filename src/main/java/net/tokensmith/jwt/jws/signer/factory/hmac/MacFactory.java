package net.tokensmith.jwt.jws.signer.factory.hmac;

import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.jws.signer.SignAlgorithm;
import net.tokensmith.jwt.jws.signer.factory.hmac.exception.SecurityKeyException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class MacFactory {
    private Base64.Decoder decoder;

    public MacFactory(Base64.Decoder decoder) {
        this.decoder = decoder;
    }

    public Key makeKey(SignAlgorithm alg, SymmetricKey jwk) {
        byte[] secretKey = decoder.decode(jwk.getKey());
        return new SecretKeySpec(secretKey, alg.getJdkAlgorithm());
    }

    public Mac makeMac(SignAlgorithm alg, SymmetricKey jwk) throws InvalidAlgorithmException, SecurityKeyException {
        java.security.Key securityKey;
        try {
            securityKey = makeKey(alg, jwk);
        } catch (IllegalArgumentException e) {
            throw new SecurityKeyException("Inappropriate key for SecretKeySpec", e);
        }
        Mac mac;

        try {
            mac = Mac.getInstance(alg.getJdkAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmException("Algorithm is not supported.", e);
        }

        try {
            mac.init(securityKey);
        } catch (java.security.InvalidKeyException e) {
            throw new SecurityKeyException("Inappropriate key for initializing MAC", e);
        }

        return mac;
    }
}
