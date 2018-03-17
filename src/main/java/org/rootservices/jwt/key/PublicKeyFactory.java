package org.rootservices.jwt.key;

import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.PublicKeyException;

import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class PublicKeyFactory {
    private KeyFactory RSAKeyFactory;

    public PublicKeyFactory(KeyFactory RSAKeyFactory) {
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
}
