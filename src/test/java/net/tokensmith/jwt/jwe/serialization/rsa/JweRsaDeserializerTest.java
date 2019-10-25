package net.tokensmith.jwt.jwe.serialization.rsa;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwe.EncryptionAlgorithm;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.AlgorithmFor;
import org.hamcrest.CoreMatchers;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jwe.entity.JWE;


import java.nio.charset.StandardCharsets;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;

public class JweRsaDeserializerTest {

    @Test
    public void stringToJWE() throws Exception {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        RSAKeyPair jwk = Factory.makeRSAKeyPairForJWE();
        JweRsaDeserializer subject = jwtAppFactory.jweRsaDeserializer();

        String compactJWE = Factory.compactJWE();

        JWE actual = subject.stringToJWE(compactJWE, jwk);

        assertThat(actual, is(notNullValue()));

        assertThat(actual.getHeader().getKeyId().isPresent(), is(false));
        assertThat(actual.getHeader().getType().isPresent(), is(false));
        assertThat(actual.getHeader().getAlgorithm(), CoreMatchers.is(Algorithm.RSAES_OAEP));
        assertThat(actual.getHeader().getAlgorithm().getAlgorithmFor(), CoreMatchers.is(AlgorithmFor.JWE));
        assertThat(actual.getHeader().getEncryptionAlgorithm().isPresent(), is(true));
        assertThat(actual.getHeader().getEncryptionAlgorithm().get(), CoreMatchers.is(EncryptionAlgorithm.AES_GCM_256));

        assertThat(actual.getCek(), is(notNullValue()));
        assertThat(actual.getIv(), is(notNullValue()));
        assertThat(actual.getAuthTag(), is(notNullValue()));

        String payload = new String(actual.getPayload(), StandardCharsets.UTF_8);
        assertThat(payload, is("The true sign of intelligence is not knowledge but imagination."));
    }
}