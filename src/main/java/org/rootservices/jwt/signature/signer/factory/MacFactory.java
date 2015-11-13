package org.rootservices.jwt.signature.signer.factory;

import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;

import javax.crypto.Mac;
import java.security.Key;

/**
 * Created by tommackenzie on 8/22/15.
 */
public interface MacFactory {
    Key makeKey(Algorithm alg, SymmetricKey jwk);
    Mac makeMac(Algorithm alg, SymmetricKey jwk);
}
