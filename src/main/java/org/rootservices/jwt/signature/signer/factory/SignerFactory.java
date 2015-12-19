package org.rootservices.jwt.signature.signer.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebKeyException;


/**
 * Created by tommackenzie on 8/22/15.
 */
public interface SignerFactory {
    Signer makeSigner(Algorithm algorithm, Key jwk) throws InvalidAlgorithmException, InvalidJsonWebKeyException;
    Signer makeMacSigner(Algorithm algorithm, Key key) throws InvalidAlgorithmException, InvalidJsonWebKeyException;
}
