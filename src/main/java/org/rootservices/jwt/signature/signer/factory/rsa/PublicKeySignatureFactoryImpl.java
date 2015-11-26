package org.rootservices.jwt.signature.signer.factory.rsa;

import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;

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
    public java.security.interfaces.RSAPublicKey makePublicKey(RSAPublicKey jwk) {
        BigInteger modulus = decode(jwk.getN());
        BigInteger publicExponent = decode(jwk.getE());

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        java.security.interfaces.RSAPublicKey publicKey = null;
        try {
            publicKey = (java.security.interfaces.RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        return publicKey;
    }

    @Override
    public Signature makeSignature(Algorithm alg, RSAPublicKey jwk) {
        java.security.interfaces.RSAPublicKey securityPublicKey = makePublicKey(jwk);

        Signature signature = null;
        try {
            signature = Signature.getInstance(SignAlgorithm.RS256.getValue());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            signature.initVerify(securityPublicKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return signature;
    }
}
