package org.rootservices.jwt.encrypt.factory;

import org.rootservices.jwt.encrypt.Transformation;
import org.rootservices.jwt.encrypt.factory.exception.CipherException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;


public class CipherRSAFactory {

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
            // https://docs.oracle.com/javase/9/docs/api/javax/crypto/spec/OAEPParameterSpec.html
            // https://security.stackexchange.com/questions/97548/breaking-down-rsa-ecb-oaepwithsha-256andmgf1padding
            spec =  OAEPParameterSpec.DEFAULT;
        }
        return spec;
    }

    protected Cipher makeCipher(Transformation transformation, Key key, int mode, AlgorithmParameterSpec spec) throws CipherException {
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

        return cipher;
    }
}
