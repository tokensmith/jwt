package net.tokensmith.jwt.jwe.factory;

import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.jwk.KeyAlgorithm;
import net.tokensmith.jwt.jwk.generator.jdk.SecretKeyGenerator;

import javax.crypto.SecretKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class SecretKeyGeneratorTest {
    private SecretKeyGenerator subject;

    @Before
    public void setUp() {
        subject = new SecretKeyGenerator();
    }
    @Test
    public void makeKeyForAESAnd256ShouldBeOk() throws Exception {
        SecretKey actual = subject.makeKey(KeyAlgorithm.AES);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is(KeyAlgorithm.AES.getValue()));
        assertThat(actual.getEncoded(), is(notNullValue()));
    }
}