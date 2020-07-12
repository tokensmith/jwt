package net.tokensmith.jwt.jwk;

import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PublicKeyException;

import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class PublicKeyTranslator {
    private KeyFactory RSAKeyFactory;

    public PublicKeyTranslator(KeyFactory RSAKeyFactory) {
        this.RSAKeyFactory = RSAKeyFactory;
    }

    /**
     * Translate net.tokensmith.jwt.entity.jwk.RSAPublicKey to a, java.security.interfaces.RSAPublicKey
     * @param from the tokensmith PublicKey (Json Web Key)
     * @return its translated instance to java.security.interfaces.RSAPublicKey
     * @throws PublicKeyException if there was a problem with the translation.
     */
    public java.security.interfaces.RSAPublicKey to(RSAPublicKey from) throws PublicKeyException {

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(from.getN(), from.getE());
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
