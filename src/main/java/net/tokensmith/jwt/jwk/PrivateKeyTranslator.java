package net.tokensmith.jwt.jwk;

import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PrivateKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;


public class PrivateKeyTranslator {
    private static final Logger LOGGER = LoggerFactory.getLogger(PrivateKeyTranslator.class);
    public static final String PRIVATE_KEY_ERROR_MSG = "Could not make RSAPrivateCrtKey";
    private KeyFactory RSAKeyFactory;

    public PrivateKeyTranslator(KeyFactory RSAKeyFactory) {
        this.RSAKeyFactory = RSAKeyFactory;
    }

    /**
     * Returns a, RSAPrivateCrtKey, which is built from the input parameter, jwk.
     * A RSAPrivateCrtKey is needed per, https://tools.ietf.org/html/rfc7517#section-9.3
     *
     * @param from a RSAKeyPair
     * @return an instance of RSAPrivateCrtKey
     * @throws PrivateKeyException if jwk is invalid.
     */
    public RSAPrivateCrtKey to(RSAKeyPair from) throws PrivateKeyException {
        RSAPrivateKeySpec keySpec;

        keySpec = new RSAPrivateCrtKeySpec(
                from.getN(), // modulus
                from.getE(), // publicExponent
                from.getD(), // privateExponent
                from.getP(), // primeP
                from.getQ(), // primeQ
                from.getDp(), // primeExponentP
                from.getDq(), // primeExponentQ
                from.getQi() // crtCoefficient
        );

        RSAPrivateCrtKey privateKey;
        try {
            privateKey = (RSAPrivateCrtKey) RSAKeyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new PrivateKeyException(PRIVATE_KEY_ERROR_MSG, e);
        }

        return privateKey;
    }
}
