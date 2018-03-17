package org.rootservices.jwt.encrypt.factory;

import org.rootservices.jwt.encrypt.Transformation;
import org.rootservices.jwt.encrypt.factory.exception.CipherException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 *  AES-GCM
 *  https://wiki.sei.cmu.edu/confluence/display/java/MSC61-J.+Do+not+use+insecure+or+weak+cryptographic+algorithms
 *  https://gist.github.com/praseodym/f2499b3e14d872fe5b4a
 *
 *  OAEP
 *  https://stackoverflow.com/questions/32161720/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding
 *  https://docs.oracle.com/javase/9/docs/api/javax/crypto/spec/OAEPParameterSpec.html
 *  https://docs.oracle.com/cd/E23943_01/security.1111/e10037/crypto.htm#BJFCICAE
 *
 *  // Additional Authenticated Data: ASCII(BASE64URL(UTF8(JWE Protected Header)))
 */
public class CipherSymmetricFactory {
    public static final int GCM_TAG_LENGTH = 16;
    public static final int GCM_IV_LENGTH = 12;
    private static SecureRandom secureRandom = new SecureRandom();

    public Cipher forEncrypt(Transformation transformation, Key key, byte[] aad) throws CipherException {

        byte[] initVector = makeInitVector();
        AlgorithmParameterSpec spec = makeSpec(transformation, initVector);
        Cipher cipher = makeCipher(transformation, key, Cipher.ENCRYPT_MODE, spec, aad);
        return cipher;
    }

    public Cipher forDecrypt(Transformation transformation, Key key, byte[] initVector, byte[] aad) throws CipherException {
        AlgorithmParameterSpec spec = makeSpec(transformation, initVector);
        Cipher cipher = makeCipher(transformation, key, Cipher.DECRYPT_MODE, spec, aad);
        return cipher;
    }

    public byte[] makeInitVector() {
        byte[] initVector = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(initVector);
        return initVector;
    }

    protected AlgorithmParameterSpec makeSpec(Transformation transformation, byte[] initVector) {
        AlgorithmParameterSpec spec = null;
        if (transformation == Transformation.AES_GCM_NO_PADDING) {
            spec = new GCMParameterSpec(GCM_TAG_LENGTH * java.lang.Byte.SIZE, initVector);
        } else if (transformation == Transformation.RSA_OAEP) {
            // https://docs.oracle.com/javase/9/docs/api/javax/crypto/spec/OAEPParameterSpec.html
            // https://security.stackexchange.com/questions/97548/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding
            spec =  OAEPParameterSpec.DEFAULT;
        }
        return spec;
    }

    protected Cipher makeCipher(Transformation transformation, Key key, int mode, AlgorithmParameterSpec spec, byte[] aad) throws CipherException {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(transformation.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new CipherException("", e);
        } catch (NoSuchPaddingException e) {
            throw new CipherException("", e);
        }

        try {
            cipher.init(mode, key, spec);
        } catch (InvalidKeyException e) {
            throw new CipherException("", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new CipherException("", e);
        }

        cipher.updateAAD(aad);
        return cipher;
    }

}
