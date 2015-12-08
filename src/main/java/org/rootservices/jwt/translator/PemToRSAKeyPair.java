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
    private KeyFactory RSAKeyFactory;

    public PemToRSAKeyPair(JcaPEMKeyConverter converter, KeyFactory RSAKeyFactory) {
        this.converter = converter;
        this.RSAKeyFactory = RSAKeyFactory;
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
                privateKey.getModulus(),
                privateKey.getPublicExponent(),
                privateKey.getPrivateExponent(),
                privateKey.getPrimeP(),
                privateKey.getPrimeQ(),
                privateKey.getPrimeExponentP(),
                privateKey.getPrimeExponentQ(),
                privateKey.getCrtCoefficient()
        );

        return rsaKeyPair;
    }
}
