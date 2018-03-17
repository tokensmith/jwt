package org.rootservices.jwt.encrypt.factory;


import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.encrypt.Transformation;
import org.rootservices.jwt.key.KeyAlgorithm;
import org.rootservices.jwt.key.SecretKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;

public class CipherSymmetricFactoryTest {

    private CipherSymmetricFactory subject;

    @Before
    public void setUp() {
        subject = new CipherSymmetricFactory();
    }

    @Test
    public void forEncryptWhenSecretKey() throws Exception {
        SecretKeyFactory secretKeyFactory = new SecretKeyFactory();
        SecretKey secretKey = secretKeyFactory.makeKey(KeyAlgorithm.AES);
        byte[] aad = Factory.aad();

        Cipher actual = subject.forEncrypt(Transformation.AES_GCM_NO_PADDING, secretKey, aad);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is(Transformation.AES_GCM_NO_PADDING.getValue()));
        assertThat(actual.getIV(), is(notNullValue()));
    }

    @Test
    public void forDecryptWhenSecretKey() throws Exception {
        SecretKeyFactory secretKeyFactory = new SecretKeyFactory();
        SecretKey secretKey = secretKeyFactory.makeKey(KeyAlgorithm.AES);
        byte[] aad = Factory.aad();

        byte[] initVector = subject.makeInitVector();
        Cipher actual = subject.forDecrypt(Transformation.AES_GCM_NO_PADDING, secretKey, initVector, aad);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is(Transformation.AES_GCM_NO_PADDING.getValue()));
        assertThat(actual.getIV(), is(notNullValue()));
        assertThat(actual.getIV(), is(initVector));
    }
}