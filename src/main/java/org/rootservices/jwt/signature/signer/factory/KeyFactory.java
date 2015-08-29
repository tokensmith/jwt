package org.rootservices.jwt.signature.signer.factory;

import org.rootservices.jwt.entity.jwt.header.Algorithm;

import java.security.Key;

/**
 * Created by tommackenzie on 8/22/15.
 */
public interface KeyFactory {
    Key makeKey(Algorithm alg, org.rootservices.jwt.entity.jwk.Key jwk);
}
