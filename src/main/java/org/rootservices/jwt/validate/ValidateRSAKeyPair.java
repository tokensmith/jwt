package org.rootservices.jwt.validate;

import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class ValidateRSAKeyPair extends ValidateKey<RSAKeyPair> {

    @Override
    public Boolean validate(RSAKeyPair key) throws InvalidKeyException {
        if (key.getKeyType() == null)
            throw new InvalidKeyException("key type is null");

        if (key.getKeyType() != KeyType.RSA )
            throw new InvalidKeyException("key type is not RSA");

        isNullOrEmpty("D", key.getD());
        isNullOrEmpty("Dp", key.getDp());
        isNullOrEmpty("Dq", key.getDq());
        isNullOrEmpty("E", key.getE());
        isNullOrEmpty("N", key.getN());
        isNullOrEmpty("P", key.getP());
        isNullOrEmpty("Q", key.getQ());
        isNullOrEmpty("Qi", key.getQi());

        return true;
    }
}
