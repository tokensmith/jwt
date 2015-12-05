package org.rootservices.jwt.translator;

import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.Use;

import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Optional;

/**
 * Created by tommackenzie on 11/30/15.
 */
public class PemToRSAKeyPair {

    private JcaPEMKeyConverter converter;
    private Base64.Encoder encoder;
    private KeyFactory RSAKeyFactory;

    public PemToRSAKeyPair(JcaPEMKeyConverter converter, Base64.Encoder encoder, KeyFactory RSAKeyFactory) {
        this.converter = converter;
        this.encoder = encoder;
        this.RSAKeyFactory = RSAKeyFactory;
    }

    private String encode(BigInteger value) {
        return encoder.encodeToString(value.toByteArray());
    }

    public RSAKeyPair translate(FileReader pemFileReader, Optional<String> keyId, Use use) {
        PEMParser pemParser = new PEMParser(pemFileReader);

        Object pemObject = null;
        try {
            pemObject = pemParser.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        }

        KeyPair keyPair = null;
        PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;

        try {
            keyPair = converter.getKeyPair(pemKeyPair);
        } catch (PEMException e) {
            e.printStackTrace();
        }

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
