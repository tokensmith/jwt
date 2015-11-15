package org.rootservices.jwt.signature.signer.factory;

import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import sun.security.rsa.RSAPublicKeyImpl;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
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

        java.security.interfaces.RSAPublicKey publicKey = null;
        try {
            // TODO: replace RSAPublicKeyImpl
            // http://stackoverflow.com/questions/29622811/open-source-replacement-for-sun-security-rsa-rsapublickeyimpl
            publicKey = new RSAPublicKeyImpl(modulus, publicExponent);
        } catch (InvalidKeyException e) {
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
