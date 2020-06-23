package net.tokensmith.jwt.jws.signer.factory.rsa;

import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.jws.signer.SignAlgorithm;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.RSAPublicKeyException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class PublicKeySignatureFactory {

    private KeyFactory RSAKeyFactory;

    public PublicKeySignatureFactory(KeyFactory RSAKeyFactory) {
        this.RSAKeyFactory = RSAKeyFactory;
    }

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

    public Signature makeSignature(SignAlgorithm alg, RSAPublicKey jwk) throws InvalidAlgorithmException, RSAPublicKeyException, InvalidJsonWebKeyException {
        java.security.PublicKey securityPublicKey;
        try {
            securityPublicKey = makePublicKey(jwk);
        } catch (PublicKeyException e) {
            throw new InvalidJsonWebKeyException("jwk is invalid", e);
        }

        Signature signature;
        try {
            signature = Signature.getInstance(alg.getJdkAlgorithm());
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
