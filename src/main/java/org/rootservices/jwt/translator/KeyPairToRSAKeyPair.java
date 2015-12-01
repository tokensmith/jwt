package org.rootservices.jwt.translator;

import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.Use;

import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Optional;


/**
 * Created by tommackenzie on 11/26/15.
 *
 * Translates a, java.security.KeyPair to org.rootservices.jwt.entity.jwk.RSAKeyPair
 */
public class KeyPairToRSAKeyPair {

    private Base64.Encoder encoder;
    private KeyFactory RSAKeyFactory;

    public KeyPairToRSAKeyPair(Base64.Encoder encoder, KeyFactory RSAKeyFactory) {
        this.encoder = encoder;
        this.RSAKeyFactory = RSAKeyFactory;
    }

    private String encode(BigInteger value) {
        return encoder.encodeToString(value.toByteArray());
    }

    public RSAKeyPair toRSAKeyPair(KeyPair keyPair, Optional<String> keyId, Use use) {

        RSAPrivateCrtKeySpec privateKey = null;
        try {
            privateKey = RSAKeyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateCrtKeySpec.class);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        RSAKeyPair rsaKeyPair = new RSAKeyPair(
                keyId,
                KeyType.RSA,
                use,
                encode(privateKey.getModulus()),
                encode(privateKey.getPublicExponent()),
                encode(privateKey.getPrivateExponent()),
                encode(privateKey.getPrimeP()),
                encode(privateKey.getPrimeQ()),
                encode(privateKey.getPrimeExponentP()),
                encode(privateKey.getPrimeExponentQ()),
                encode(privateKey.getCrtCoefficient())
        );

        return rsaKeyPair;
    }
}
