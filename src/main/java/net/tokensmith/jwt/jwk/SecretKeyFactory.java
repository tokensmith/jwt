package net.tokensmith.jwt.jwk;

import net.tokensmith.jwt.jwk.exception.SecretKeyException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;


public class SecretKeyFactory {
    public static final String MESSAGE = "Could not construct key generator";
    private static int keySize = 256;

    public SecretKey makeKey(KeyAlgorithm keyAlgorithm) throws SecretKeyException {
        // docs say KeyGenerators can be reused as long as they use the same init values.
        // Depending on the cost to create these this could be held onto for future use.
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(keyAlgorithm.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new SecretKeyException(MESSAGE, e);
        }

        keyGenerator.init(keySize);

        return keyGenerator.generateKey();
    }
}
