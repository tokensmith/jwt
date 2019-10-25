package net.tokensmith.jwt.jws.signer.factory.rsa;

import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.jws.signer.SignAlgorithm;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PrivateKeyException;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.RSAPrivateKeyException;

import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;

/**
 * Created by tommackenzie on 11/4/15.
 */
public class PrivateKeySignatureFactory {

    private KeyFactory RSAKeyFactory;

    public PrivateKeySignatureFactory(KeyFactory RSAKeyFactory) {
        this.RSAKeyFactory = RSAKeyFactory;
    }

    /**
     * Returns a, RSAPrivateCrtKey, which is built from the input parameter, jwk.
     * A RSAPrivateCrtKey is needed per, https://tools.ietf.org/html/rfc7517#section-9.3
     *
     * @param jwk a RSAKeyPair
     * @return an instance of RSAPrivateCrtKey
     * @throws PrivateKeyException if jwk is invalid.
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

    public Signature makeSignature(SignAlgorithm alg, RSAKeyPair jwk) throws PrivateKeyException, InvalidAlgorithmException, RSAPrivateKeyException {
        RSAPrivateKey privateKey = makePrivateKey(jwk);

        Signature signature;

        try {
            signature = Signature.getInstance(alg.getJdkAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidAlgorithmException("Algorithm is not supported.", e);
        }

        try {
            signature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            // should never reach here - it will fail creating the key first
            throw new RSAPrivateKeyException("Failed adding key to Signature", e);
        }
        return signature;
    }
}
