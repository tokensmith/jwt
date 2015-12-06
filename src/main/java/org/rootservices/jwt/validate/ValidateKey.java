package org.rootservices.jwt.validate;

import org.rootservices.jwt.entity.jwk.Key;

/**
 * Created by tommackenzie on 12/6/15.
 */
public abstract class ValidateKey <T extends Key> {

    abstract Boolean validate(T key) throws InvalidKeyException;

    protected Boolean isNullOrEmpty(String parameter, String value) throws InvalidKeyException {
        if (value == null)
            throw new InvalidKeyException(parameter + " is null");

        if (value.isEmpty())
            throw new InvalidKeyException(parameter + " is empty");

        return true;
    }

}
