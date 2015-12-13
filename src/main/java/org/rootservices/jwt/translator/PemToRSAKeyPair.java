package org.rootservices.jwt.translator;

import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.Use;
import org.rootservices.jwt.exception.InvalidKeyException;
import org.rootservices.jwt.translator.exception.InvalidPemException;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
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


    public RSAKeyPair translate(FileReader pemFileReader, Optional<String> keyId, Use use) throws InvalidPemException, InvalidKeyException {
        PEMParser pemParser = new PEMParser(pemFileReader);

        PEMKeyPair pemKeyPair = null;
        try {
            pemKeyPair = (PEMKeyPair) pemParser.readObject();
        } catch (IOException e) {
            throw new InvalidPemException("invalid file reader", e);
        } catch (ClassCastException e) {
            throw new InvalidPemException("pem did not not have a key pair", e);
        }

        if (pemKeyPair == null) {
            throw new InvalidPemException("Could not parse the file reader");
        }

        KeyPair keyPair = null;
        try {
            keyPair = converter.getKeyPair(pemKeyPair);
        } catch (PEMException e) {
            throw new InvalidPemException("Could not translate PEMKeyPair to a KeyPair");
        }

        RSAPrivateCrtKeySpec privateKey = null;
        try {
            privateKey = RSAKeyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateCrtKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Could not create RSAPrivateCrtKeySpec", e);
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
