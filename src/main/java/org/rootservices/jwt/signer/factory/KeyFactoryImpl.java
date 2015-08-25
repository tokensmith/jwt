package org.rootservices.jwt.signer.factory;

import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signer.SignAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class KeyFactoryImpl implements KeyFactory {
    @Override
    public Key makeKey(Algorithm alg, org.rootservices.jwt.entity.jwk.Key jwk) {
        Key key = null;

        if (alg == Algorithm.HS256 && jwk.getKeyType() == KeyType.OCT) {
            byte[] secretKey = Base64.getUrlDecoder().decode(jwk.getKey());
            key = new SecretKeySpec(secretKey, SignAlgorithm.HS256.getValue());
        }
        return key;
    }
}
