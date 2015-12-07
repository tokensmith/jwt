package org.rootservices.jwt.signature.verifier.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.factory.exception.SignerException;
import org.rootservices.jwt.signature.verifier.VerifySignature;

import java.security.SignatureException;

/**
 * Created by tommackenzie on 11/15/15.
 */
public interface VerifySignatureFactory {
    VerifySignature makeVerifySignature(Algorithm algorithm, Key key) throws SignerException, SignatureException;
}
