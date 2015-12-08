package org.rootservices.jwt.signature.signer.factory.hmac;

import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.factory.hmac.exception.MacException;

import javax.crypto.Mac;
import java.security.Key;

/**
 * Created by tommackenzie on 8/22/15.
 */
public interface MacFactory {
    Key makeKey(Algorithm alg, SymmetricKey jwk);
    Mac makeMac(Algorithm alg, SymmetricKey jwk) throws MacException;
}