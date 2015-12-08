package org.rootservices.jwt.signature.signer.factory.rsa;

import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.PublicKeyException;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64.Decoder;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class PublicKeySignatureFactoryImpl implements PublicKeySignatureFactory {

    private Decoder decoder;

    public PublicKeySignatureFactoryImpl(Decoder decoder) {
        this.decoder = decoder;
    }

    private BigInteger decode(String value) {
        byte[] decodedBytes = decoder.decode(value);
        return new BigInteger(1, decodedBytes);
    }

    @Override
    public java.security.interfaces.RSAPublicKey makePublicKey(RSAPublicKey jwk) throws PublicKeyException {
        BigInteger modulus = decode(jwk.getN());
        BigInteger publicExponent = decode(jwk.getE());

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            // should never reach here - tests prove it.
            throw new PublicKeyException("Could not make KeyFactory", e);
        }

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        java.security.interfaces.RSAPublicKey publicKey = null;
        try {
            publicKey = (java.security.interfaces.RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
        } catch (InvalidKeySpecException e) {
            // will only reach here if there's something wrong with the rsa public key
            throw new PublicKeyException("Could not make java.security.interfaces.RSAPublicKey", e);
        }

        return publicKey;
    }

    @Override
    public Signature makeSignature(Algorithm alg, RSAPublicKey jwk) throws SignatureException {
        java.security.interfaces.RSAPublicKey securityPublicKey = null;
        try {
            securityPublicKey = makePublicKey(jwk);
        } catch (PublicKeyException e) {
            throw new SignatureException("Could not make java.security.interfaces.RSAPublicKey", e);
        }

        Signature signature = null;
        try {
            signature = Signature.getInstance(SignAlgorithm.RS256.getValue());
        } catch (NoSuchAlgorithmException e) {
            // should never reach here - tests prove it.
            throw new SignatureException("Could not create Signature", e);
        }

        try {
            signature.initVerify(securityPublicKey);
        } catch (InvalidKeyException e) {
            // should never reach here - it will fail creating the key first
            throw new SignatureException("Failed adding key to Signature", e);
        }

        return signature;
    }
}
