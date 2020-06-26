package net.tokensmith.jwt.jwk.generator.jdk;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

public class RSAPrivateCrtKeyGenerator {
    private KeyPairGenerator keyPairGenerator;
    private KeyFactory keyFactory;


    public RSAPrivateCrtKeyGenerator(KeyPairGenerator keyPairGenerator, KeyFactory keyFactory) {
        this.keyPairGenerator = keyPairGenerator;
        this.keyFactory = keyFactory;
    }

    protected synchronized PrivateKey makePrivateKey(int keySize) {

        // not thread safe so its synchronized ^
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        return keyPair.getPrivate();
    }

    protected RSAPrivateCrtKey makeRSAPrivateCrtKey(PrivateKey privateKey) throws InvalidKeySpecException{

        RSAPrivateCrtKeySpec rsaPrivateCrtKeySpec = null;
        try {
            rsaPrivateCrtKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);
        } catch (InvalidKeySpecException e) {
            throw e;
        }

        RSAPrivateCrtKey rsaPrivateCrtKey = null;
        try {
            rsaPrivateCrtKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(rsaPrivateCrtKeySpec);
        } catch (InvalidKeySpecException e) {
            throw e;
        }

        return rsaPrivateCrtKey;
    }

    public RSAPrivateCrtKey generate(int keySize) throws InvalidKeySpecException {
        PrivateKey privateKey = makePrivateKey(keySize);
        return makeRSAPrivateCrtKey(privateKey);
    }
}
