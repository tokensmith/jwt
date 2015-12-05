package org.rootservices.jwt.signature.signer.factory.rsa;

import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;

import java.security.PublicKey;
import java.security.Signature;

/**
 * Created by tommackenzie on 11/14/15.
 */
public interface PublicKeySignatureFactory {
    java.security.interfaces.RSAPublicKey makePublicKey(RSAPublicKey jwk);
    Signature makeSignature(Algorithm alg, RSAPublicKey jwk);
}
