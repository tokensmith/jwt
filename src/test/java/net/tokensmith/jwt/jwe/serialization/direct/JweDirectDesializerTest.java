package net.tokensmith.jwt.jwe.serialization.direct;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwe.EncryptionAlgorithm;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.AlgorithmFor;
import org.hamcrest.CoreMatchers;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jwe.entity.JWE;
import net.tokensmith.jwt.jwe.serialization.JweDeserializer;
import net.tokensmith.jwt.jwe.serialization.exception.KeyException;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

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

    @Test
    public void stringToJWEWhenKeyIsNotBase64ShouldThrowKeyException() throws Exception {
        JweDirectDesializer subject = jwtAppFactory.jweDirectDesializer();

        SymmetricKey key = Factory.makeSymmetricKeyForJWE();
        key.setKey("=bad-key=");
        String compactJwe = Factory.symmetricCompactJWE();

        KeyException actual = null;
        try {
            subject.stringToJWE(compactJwe, key);
        } catch (KeyException e) {
            actual = e;
        }

        assertThat(actual, is(notNullValue()));
    }
}