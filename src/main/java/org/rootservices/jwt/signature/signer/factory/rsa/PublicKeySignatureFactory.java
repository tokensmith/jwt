package org.rootservices.jwt.signature.signer.factory.rsa;

import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.PublicKeyException;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.RSAPublicKeyException;
import java.security.Signature;


/**
 * Created by tommackenzie on 11/14/15.
 */
public interface PublicKeySignatureFactory {
    java.security.interfaces.RSAPublicKey makePublicKey(RSAPublicKey jwk) throws PublicKeyException;
    Signature makeSignature(SignAlgorithm alg, RSAPublicKey jwk) throws PublicKeyException, InvalidAlgorithmException, RSAPublicKeyException;
}
