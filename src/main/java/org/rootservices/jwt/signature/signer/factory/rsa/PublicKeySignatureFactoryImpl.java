package org.rootservices.jwt.signature.signer.factory.rsa;

import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.PublicKeyException;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.RSAPublicKeyException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class PublicKeySignatureFactoryImpl implements PublicKeySignatureFactory {

    private KeyFactory RSAKeyFactory;

    public PublicKeySignatureFactoryImpl(KeyFactory RSAKeyFactory) {
        this.RSAKeyFactory = RSAKeyFactory;
    }

    @Override
    public java.security.interfaces.RSAPublicKey makePublicKey(RSAPublicKey jwk) throws PublicKeyException {

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(jwk.getN(), jwk.getE());
        java.security.interfaces.RSAPublicKey publicKey = null;
        try {
            publicKey = (java.security.interfaces.RSAPublicKey) RSAKeyFactory.generatePublic(rsaPublicKeySpec);
        } catch (InvalidKeySpecException e) {
            // will only reach here if there's something wrong with the RSAPublicKey
            throw new PublicKeyException("Could not make java.security.interfaces.RSAPublicKey", e);
        }

        return publicKey;
    }

    @Override
    public Signature makeSignature(SignAlgorithm alg, RSAPublicKey jwk) throws PublicKeyException, InvalidAlgorithmException, RSAPublicKeyException {
        java.security.interfaces.RSAPublicKey securityPublicKey = makePublicKey(jwk);

        Signature signature = null;
        try {
            signature = Signature.getInstance(alg.getValue());
        } catch (NoSuchAlgorithmException e) {
            // should never reach here - tests prove it.
            throw new InvalidAlgorithmException("Could not create Signature", e);
        }

        try {
            signature.initVerify(securityPublicKey);
        } catch (InvalidKeyException e) {
            // should never reach here - it will fail creating the key first
            throw new RSAPublicKeyException("Failed adding key to Signature", e);
        }

        return signature;
    }
}
