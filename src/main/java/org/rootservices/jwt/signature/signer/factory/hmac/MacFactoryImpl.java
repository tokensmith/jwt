package org.rootservices.jwt.signature.signer.factory.hmac;

import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.SecurityKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class MacFactoryImpl implements MacFactory {
    private Base64.Decoder decoder;

    public MacFactoryImpl(Base64.Decoder decoder) {
        this.decoder = decoder;
    }

    @Override
    public Key makeKey(Algorithm alg, SymmetricKey jwk) {
        byte[] secretKey = decoder.decode(jwk.getKey());
        return new SecretKeySpec(secretKey, SignAlgorithm.HS256.getValue());
    }

    @Override
    public Mac makeMac(Algorithm alg, SymmetricKey jwk) throws InvalidAlgorithmException, SecurityKeyException {
        java.security.Key securityKey = makeKey(alg, jwk);
        Mac mac;

        try {
            mac = Mac.getInstance(SignAlgorithm.HS256.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmException("Algorithm is not supported.", e);
        }

        try {
            mac.init(securityKey);
        } catch (java.security.InvalidKeyException e) {
            // should never reach here - it will fail creating the key first
            throw new SecurityKeyException("Inappropriate key for initializing MAC", e);
        }

        return mac;
    }
}
