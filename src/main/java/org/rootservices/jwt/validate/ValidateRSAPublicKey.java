package org.rootservices.jwt.validate;

import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class ValidateRSAPublicKey extends ValidateKey<RSAPublicKey> {

    @Override
    public Boolean validate(RSAPublicKey key) throws InvalidKeyException {
        if (key.getKeyType() == null)
            throw new InvalidKeyException("key type is null");

        if (key.getKeyType() != KeyType.RSA )
            throw new InvalidKeyException("key type is not RSA");

        isNullOrEmpty("N", key.getN());
        isNullOrEmpty("E", key.getE());

        return true;
    }

}
