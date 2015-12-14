package org.rootservices.jwt.signature.signer.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebTokenException;
import org.rootservices.jwt.signature.signer.factory.exception.SignerException;


/**
 * Created by tommackenzie on 8/22/15.
 */
public interface SignerFactory {
    Signer makeSigner(Algorithm algorithm, Key jwk) throws InvalidAlgorithmException, InvalidJsonWebTokenException;
    Signer makeMacSigner(Algorithm algorithm, Key key) throws InvalidAlgorithmException, InvalidJsonWebTokenException;
}
