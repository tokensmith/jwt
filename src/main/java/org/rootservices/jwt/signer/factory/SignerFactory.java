package org.rootservices.jwt.signer.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signer.Signer;

/**
 * Created by tommackenzie on 8/22/15.
 */
public interface SignerFactory {
    Signer makeSigner(Algorithm algorithm, Key jwk);
}
