package org.rootservices.jwt.validate;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class ValidateSymmetricKey {

    public Boolean validate(SymmetricKey key) {

        if (key.getKeyType() == null) {

        }

        if (key.getKeyType() != KeyType.OCT ) {

        }

        return true;
    }
}
