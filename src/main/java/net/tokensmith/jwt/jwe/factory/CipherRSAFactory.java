package net.tokensmith.jwt.jwe.factory;

import net.tokensmith.jwt.jwe.Transformation;
import net.tokensmith.jwt.jwe.factory.exception.CipherException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * https://docs.oracle.com/javase/9/docs/api/javax/crypto/spec/OAEPParameterSpec.html
 * https://security.stackexchange.com/questions/97548/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding
 */
public class CipherRSAFactory {
    public static final String ALGORITHM_WAS_INVALID = "Algorithm, %s, was invalid";
    public static final String PADDING_WAS_INVALID = "Padding for algorithm, %s, was invalid";
    public static final String KEY_WAS_INVALID_INIT_CIPHER = "Key was invalid when initializing cipher";
    public static final String ALGORITHM_WAS_INVALID_INIT_CIPHER = "Algorithm, %s, was invalid when initializing cipher";

    public Cipher forEncrypt(Transformation transformation, Key key) throws CipherException {
        AlgorithmParameterSpec spec = makeSpec(transformation);
        Cipher cipher = makeCipher(transformation, key, Cipher.ENCRYPT_MODE, spec);
        return cipher;
    }

    public Cipher forDecrypt(Transformation transformation, Key key) throws CipherException {
        AlgorithmParameterSpec spec = makeSpec(transformation);
        Cipher cipher = makeCipher(transformation, key, Cipher.DECRYPT_MODE, spec);
        return cipher;
    }

    protected AlgorithmParameterSpec makeSpec(Transformation transformation) {
        AlgorithmParameterSpec spec = null;
        if (transformation == Transformation.RSA_OAEP) {
            spec =  OAEPParameterSpec.DEFAULT;
        }
        return spec;
    }

    protected Cipher makeCipher(Transformation transformation, Key key, int mode, AlgorithmParameterSpec spec) throws CipherException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformation.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new CipherException(String.format(ALGORITHM_WAS_INVALID, transformation.getValue()), e);
        } catch (NoSuchPaddingException e) {
            throw new CipherException(String.format(PADDING_WAS_INVALID, transformation.getValue()), e);
        }

        try {
            cipher.init(mode, key, spec);
        } catch (InvalidKeyException e) {
            throw new CipherException(KEY_WAS_INVALID_INIT_CIPHER, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CipherException(String.format(ALGORITHM_WAS_INVALID_INIT_CIPHER, transformation.getValue()), e);
        }

        return cipher;
    }
}
