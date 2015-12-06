package org.rootservices.jwt.validate;

import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class ValidateSymmetricKey extends ValidateKey<SymmetricKey> {

    @Override
    public Boolean validate(SymmetricKey key) throws InvalidKeyException {

        if (key.getKeyType() == null)
            throw new InvalidKeyException("key type is null");

        if (key.getKeyType() != KeyType.OCT )
            throw new InvalidKeyException("key type is not OCT");

        isNullOrEmpty("key", key.getKey());

        return true;
    }
}
