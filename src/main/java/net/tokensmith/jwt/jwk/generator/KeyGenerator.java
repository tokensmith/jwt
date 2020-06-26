package net.tokensmith.jwt.jwk.generator;

import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwk.Use;
import net.tokensmith.jwt.jwk.KeyAlgorithm;
import net.tokensmith.jwt.jwk.exception.SecretKeyException;
import net.tokensmith.jwt.jwk.generator.exception.KeyGenerateException;
import net.tokensmith.jwt.jwk.generator.jdk.RSAPrivateCrtKeyGenerator;
import net.tokensmith.jwt.jwk.generator.jdk.SecretKeyGenerator;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;
import java.util.UUID;

/**
 * Generates keys
 *
 */
public class KeyGenerator {
    public static int RSA_1024 = 1024;
    public static int RSA_2048 = 2048;
    public static int RSA_4096 = 4096;

    private SecretKeyGenerator secretKeyGenerator;
    private RSAPrivateCrtKeyGenerator rsaKeyGenerator;

    public KeyGenerator(SecretKeyGenerator secretKeyGenerator, RSAPrivateCrtKeyGenerator rsaKeyGenerator) {
        this.secretKeyGenerator = secretKeyGenerator;
        this.rsaKeyGenerator = rsaKeyGenerator;
    }

    private SecretKey secretKey() throws SecretKeyException {
        return secretKeyGenerator.makeKey(KeyAlgorithm.AES);
    }

    public SymmetricKey symmetricKey(Optional<String> keyId, Use use) throws KeyGenerateException {
        SecretKey secretKey = null;
        try {
            secretKey = secretKey();
        } catch (SecretKeyException e) {
            throw new KeyGenerateException("Could not generate secret key", e);
        }

        return translate(secretKey, keyId, use);
    }

    public RSAKeyPair rsaKeyPair(int keySize, Optional<String> keyId, Use use) throws KeyGenerateException {
        RSAPrivateCrtKey jdkKey;
        try {
            jdkKey = rsaKeyGenerator.generate(keySize);
        } catch (InvalidKeySpecException e) {
            throw new KeyGenerateException("Could not generate RSA key pair", e);

        }
        return translate(jdkKey, keyId, use);
    }

    private SymmetricKey translate(SecretKey from, Optional<String> keyId, Use use) {
        return new SymmetricKey.Builder()
                .keyId(keyId)
                .use(use)
                .key(new String(from.getEncoded(), StandardCharsets.UTF_8))
                .build();
    }

    private RSAKeyPair translate(RSAPrivateCrtKey from, Optional<String> keyId, Use use) {
        return new RSAKeyPair.Builder()
                .keyId(keyId)
                .use(use)
                .n(from.getModulus())
                .e(from.getPublicExponent())
                .d(from.getPrivateExponent())
                .p(from.getPrimeP())
                .q(from.getPrimeQ())
                .dp(from.getPrimeExponentP())
                .dq(from.getPrimeExponentQ())
                .qi(from.getCrtCoefficient())
                .build();
    }
}
