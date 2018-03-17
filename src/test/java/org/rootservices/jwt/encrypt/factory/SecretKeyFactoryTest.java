package org.rootservices.jwt.encrypt.factory;

import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.key.KeyAlgorithm;
import org.rootservices.jwt.key.SecretKeyFactory;

import javax.crypto.SecretKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;

public class SecretKeyFactoryTest {
    private SecretKeyFactory subject;

    @Before
    public void setUp() {
        subject = new SecretKeyFactory();
    }
    @Test
    public void makeKeyForAESAnd256ShouldBeOk() {
        SecretKey actual = subject.makeKey(KeyAlgorithm.AES);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is(KeyAlgorithm.AES.getValue()));
        assertThat(actual.getEncoded(), is(notNullValue()));
    }
}