package org.rootservices.jwt.signature.verifier.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.verifier.VerifySignature;

/**
 * Created by tommackenzie on 11/15/15.
 */
public interface VerifySignatureFactory {
    VerifySignature makeVerifySignature(Algorithm algorithm, Key key);
}
