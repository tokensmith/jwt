package org.rootservices.jwt.signature.signer.factory.rsa;

import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.PrivateKeyException;

import java.net.URI;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;


/**
 * Created by tommackenzie on 11/4/15.
 */
public interface PrivateKeySignatureFactory {
    RSAPrivateCrtKey makePrivateKey(RSAKeyPair jwk) throws PrivateKeyException;
    Signature makeSignature(Algorithm alg, RSAKeyPair jwk) throws SignatureException;
}
