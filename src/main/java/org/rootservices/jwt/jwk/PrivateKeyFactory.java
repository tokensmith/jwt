package org.rootservices.jwt.jwk;

import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PrivateKeyException;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;

public class PrivateKeyFactory {
    private KeyFactory RSAKeyFactory;

    public PrivateKeyFactory(KeyFactory RSAKeyFactory) {
        this.RSAKeyFactory = RSAKeyFactory;
    }

    /**
     * Returns a, RSAPrivateCrtKey, which is built from the input parameter, jwk.
     * A RSAPrivateCrtKey is needed per, https://tools.ietf.org/html/rfc7517#section-9.3
     *
     * @param jwk
     * @return
     */
    public RSAPrivateCrtKey makePrivateKey(RSAKeyPair jwk) throws PrivateKeyException {
        RSAPrivateKeySpec keySpec;

        keySpec = new RSAPrivateCrtKeySpec(
                jwk.getN(), // modulus
                jwk.getE(), // publicExponent
                jwk.getD(), // privateExponent
                jwk.getP(), // primeP
                jwk.getQ(), // primeQ
                jwk.getDp(), // primeExponentP
                jwk.getDq(), // primeExponentQ
                jwk.getQi() // crtCoefficient
        );

        RSAPrivateCrtKey privateKey;
        try {
            privateKey = (RSAPrivateCrtKey) RSAKeyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new PrivateKeyException("Could not make RSAPrivateCrtKey", e);
        }

        return privateKey;
    }
}
