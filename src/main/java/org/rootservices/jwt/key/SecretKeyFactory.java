package org.rootservices.jwt.key;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;


public class SecretKeyFactory {
    private static int keySize = 256;

    public SecretKey makeKey(KeyAlgorithm keyAlgorithm) {
        // docs say KeyGenerators can be reused as long as they use the same init values.
        // Depending on the cost to create these this could be held onto for future use.
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(keyAlgorithm.getValue());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        keyGenerator.init(keySize);

        return keyGenerator.generateKey();
    }
}
