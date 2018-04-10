package org.rootservices.jwt.serialization;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwe.EncryptionAlgorithm;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.AlgorithmFor;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.exception.InvalidJWT;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;

public class HeaderDeserializerTest {
    private HeaderDeserializer subject;

    @Before
    public void setUp() {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        subject = jwtAppFactory.headerDeserializer();
    }

    @Test
    public void toHeader() throws Exception {
        // https://tools.ietf.org/html/rfc7516#section-3.3
        String compactJWE = Factory.compactJWE();
        Header actual = subject.toHeader(compactJWE);

        assertThat(actual, is(notNullValue()));

        assertThat(actual.getKeyId().isPresent(), is(false));
        assertThat(actual.getType().isPresent(), is(false));
        assertThat(actual.getAlgorithm(), is(Algorithm.RSAES_OAEP));
        assertThat(actual.getAlgorithm().getAlgorithmFor(), is(AlgorithmFor.JWE));
        assertThat(actual.getEncryptionAlgorithm().isPresent(), is(true));
        assertThat(actual.getEncryptionAlgorithm().get(), is(EncryptionAlgorithm.AES_GCM_256));
    }

    @Test
    public void toHeaderShouldThrowInvalidJwt() throws Exception {
        String compactJWE = "";

        InvalidJWT actual = null;
        try {
            subject.toHeader(compactJWE);
        } catch (InvalidJWT e) {
            actual = e;
        }

        assertThat(actual, is(notNullValue()));
    }
}