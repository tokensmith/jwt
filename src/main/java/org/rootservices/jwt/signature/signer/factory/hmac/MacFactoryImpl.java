package org.rootservices.jwt.signature.signer.factory.hmac;

import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;

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

    @Override
    public Key makeKey(Algorithm alg, SymmetricKey jwk) {
        Key key = null;

        if (alg == Algorithm.HS256 && jwk.getKeyType() == KeyType.OCT) {
            byte[] secretKey = Base64.getUrlDecoder().decode(jwk.getKey());
            key = new SecretKeySpec(secretKey, SignAlgorithm.HS256.getValue());
        }
        return key;
    }

    @Override
    public Mac makeMac(Algorithm alg, SymmetricKey jwk) {
        java.security.Key securityKey = makeKey(alg, (SymmetricKey) jwk);
        Mac mac = null;

        try {
            mac = Mac.getInstance(securityKey.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            mac.init(securityKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return mac;
    }
}
