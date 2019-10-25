package net.tokensmith.jwt.serialization;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwe.EncryptionAlgorithm;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.AlgorithmFor;
import net.tokensmith.jwt.entity.jwt.header.Header;
import net.tokensmith.jwt.exception.InvalidJWT;
import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;

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
        assertThat(actual.getAlgorithm(), CoreMatchers.is(Algorithm.RSAES_OAEP));
        assertThat(actual.getAlgorithm().getAlgorithmFor(), CoreMatchers.is(AlgorithmFor.JWE));
        assertThat(actual.getEncryptionAlgorithm().isPresent(), is(true));
        assertThat(actual.getEncryptionAlgorithm().get(), CoreMatchers.is(EncryptionAlgorithm.AES_GCM_256));
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