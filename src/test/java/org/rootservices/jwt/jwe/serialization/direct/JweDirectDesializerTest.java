package org.rootservices.jwt.jwe.serialization.direct;

import helper.entity.Factory;
import org.hamcrest.CoreMatchers;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwe.EncryptionAlgorithm;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.AlgorithmFor;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.serialization.JweDeserializer;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.*;

public class JweDirectDesializerTest {
    private static JwtAppFactory jwtAppFactory = new JwtAppFactory();

    @Test
    public void stringToJWE() throws Exception {
        JweDeserializer subject = jwtAppFactory.jweDirectDesializer();

        SymmetricKey key = Factory.makeSymmetricKeyForJWE();
        String compactJwe = Factory.symmetricCompactJWE();

        JWE actual = subject.stringToJWE(compactJwe, key);

        assertThat(actual, is(notNullValue()));

        assertThat(actual.getHeader().getKeyId().isPresent(), CoreMatchers.is(false));
        assertThat(actual.getHeader().getType().isPresent(), CoreMatchers.is(false));
        assertThat(actual.getHeader().getAlgorithm(), CoreMatchers.is(Algorithm.DIRECT));
        assertThat(actual.getHeader().getAlgorithm().getAlgorithmFor(), CoreMatchers.is(AlgorithmFor.JWE));
        assertThat(actual.getHeader().getEncryptionAlgorithm().isPresent(), CoreMatchers.is(true));
        assertThat(actual.getHeader().getEncryptionAlgorithm().get(), CoreMatchers.is(EncryptionAlgorithm.AES_GCM_256));

        assertThat(actual.getCek(), CoreMatchers.is(CoreMatchers.notNullValue()));
        assertThat(actual.getIv(), CoreMatchers.is(CoreMatchers.notNullValue()));
        assertThat(actual.getAuthTag(), CoreMatchers.is(CoreMatchers.notNullValue()));

        String payload = new String(actual.getPayload(), StandardCharsets.UTF_8);
        assertThat(payload, CoreMatchers.is("Help me, Obi-Wan Kenobi. You're my only hope."));
    }
}