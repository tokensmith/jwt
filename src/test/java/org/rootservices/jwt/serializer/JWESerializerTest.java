package org.rootservices.jwt.serializer;

import helper.entity.Factory;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwe.EncryptionAlgorithm;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.AlgorithmFor;
import org.rootservices.jwt.jwe.entity.JWE;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;

public class JWESerializerTest {

    @Test
    public void stringToJWE() throws Exception {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        RSAKeyPair jwk = Factory.makeRSAKeyPairForJWE();
        JWESerializer subject = jwtAppFactory.jweSerializer(jwk);

        String compactJWE = Factory.compactJWE();

        JWE actual = subject.stringToJWE(compactJWE);

        assertThat(actual, is(notNullValue()));

        assertThat(actual.getHeader().getKeyId().isPresent(), is(false));
        assertThat(actual.getHeader().getType().isPresent(), is(false));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.RSAES_OAEP));
        assertThat(actual.getHeader().getAlgorithm().getAlgorithmFor(), is(AlgorithmFor.JWE));
        assertThat(actual.getHeader().getEncryptionAlgorithm().isPresent(), is(true));
        assertThat(actual.getHeader().getEncryptionAlgorithm().get(), is(EncryptionAlgorithm.AES_GCM_256));

        assertThat(actual.getCek(), is(notNullValue()));
        assertThat(actual.getIv(), is(notNullValue()));
        assertThat(actual.getAuthTag(), is(notNullValue()));

        String payload = new String(actual.getPayload(), StandardCharsets.UTF_8);
        assertThat(payload, is("The true sign of intelligence is not knowledge but imagination."));
    }
}