package org.rootservices.jwt.signature.signer.factory.hmac;

import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.hmac.exception.MacException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
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
        Key key = null;

        if (alg == Algorithm.HS256 && jwk.getKeyType() == KeyType.OCT) {
            byte[] secretKey = decoder.decode(jwk.getKey());
            key = new SecretKeySpec(secretKey, SignAlgorithm.HS256.getValue());
        }
        return key;
    }

    @Override
    public Mac makeMac(Algorithm alg, SymmetricKey jwk) throws MacException {
        java.security.Key securityKey = makeKey(alg, jwk);
        Mac mac = null;

        try {
            mac = Mac.getInstance(securityKey.getAlgorithm());
            // TODO: could possibly throw a npe ^
        } catch (NoSuchAlgorithmException e) {
            // should never reach here - tests prove it.
            throw new MacException("Could not create mac", e);
        }

        try {
            mac.init(securityKey);
        } catch (InvalidKeyException e) {
            // should never reach here - it will fail creating the key first
            throw new MacException("Invalid java.security.Key", e);
        }

        return mac;
    }
}
