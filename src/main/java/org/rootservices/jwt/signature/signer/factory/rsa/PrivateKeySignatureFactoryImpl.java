package org.rootservices.jwt.signature.signer.factory.rsa;

import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.PrivateKeyException;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;

/**
 * Created by tommackenzie on 11/4/15.
 */
public class PrivateKeySignatureFactoryImpl implements PrivateKeySignatureFactory {
    private Base64.Decoder decoder;

    public PrivateKeySignatureFactoryImpl(Base64.Decoder decoder) {
        this.decoder = decoder;
    }

    private BigInteger decode(String value) {
        byte[] decodedBytes = decoder.decode(value);
        return new BigInteger(1, decodedBytes);
    }

    /**
     * Returns a, RSAPrivateCrtKey, which is built from the input parameter, jwk.
     * A RSAPrivateCrtKey is needed per, https://tools.ietf.org/html/rfc7517#section-9.3
     *
     * @param jwk
     * @return
     */
    public RSAPrivateCrtKey makePrivateKey(RSAKeyPair jwk) throws PrivateKeyException {
        RSAPrivateKeySpec keySpec = null;

        BigInteger modulus = decode(jwk.getN());
        BigInteger publicExponent = decode(jwk.getE());
        BigInteger privateExponent = decode(jwk.getD());
        BigInteger primeP = decode(jwk.getP());
        BigInteger primeQ = decode(jwk.getQ());
        BigInteger primeExponentP = decode(jwk.getDp());
        BigInteger primeExponentQ = decode(jwk.getDq());
        BigInteger crtCoefficient = decode(jwk.getQi());

        keySpec = new RSAPrivateCrtKeySpec(
                modulus,
                publicExponent,
                privateExponent,
                primeP,
                primeQ,
                primeExponentP,
                primeExponentQ,
                crtCoefficient
        );

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            // should never reach here - tests prove it.
            throw new PrivateKeyException("Could not make KeyFactory", e);
        }

        RSAPrivateCrtKey privateKey = null;
        try {
            privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            // will only reach here if there's something wrong with the rsa key pair
            throw new PrivateKeyException("Could not make RSAPrivateCrtKey", e);
        }

        return privateKey;
    }

    @Override
    public Signature makeSignature(Algorithm alg, RSAKeyPair jwk) throws SignatureException {
        RSAPrivateKey privateKey = null;
        try {
            privateKey = makePrivateKey(jwk);
        } catch (PrivateKeyException e) {
            throw new SignatureException("Could not make java.security.interfaces.RSAPrivateKey", e);
        }
        Signature signature = null;

        try {
            signature = Signature.getInstance(SignAlgorithm.RS256.getValue());
        } catch (NoSuchAlgorithmException e) {
            // should never reach here - tests prove it.
            throw new SignatureException("Could not create Signature", e);
        }

        try {
            signature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            // should never reach here - it will fail creating the key first
            throw new SignatureException("Failed adding key to Signature", e);
        }
        return signature;
    }
}
