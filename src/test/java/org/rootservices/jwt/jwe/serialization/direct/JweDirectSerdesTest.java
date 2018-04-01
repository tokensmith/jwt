package org.rootservices.jwt.jwe.serialization.direct;

import helper.entity.Factory;
import org.hamcrest.CoreMatchers;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwe.EncryptionAlgorithm;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.serialization.JweDeserializer;
import org.rootservices.jwt.jwe.serialization.JweSerializer;
import org.rootservices.jwt.jwe.serialization.rsa.JweRsaDeserializer;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.*;
import static org.mockito.Matchers.notNull;

public class JweDirectSerdesTest {
    private static JwtAppFactory jwtAppFactory = new JwtAppFactory();

    @Test
    public void JWEToCompact() throws Exception {
        JweSerializer subject = jwtAppFactory.jweDirectSerializer();

        SymmetricKey key = Factory.makeSymmetricKeyForJWE();

        Base64.Decoder decoder = jwtAppFactory.urlDecoder();

        Header header = new Header();
        header.setEncryptionAlgorithm(Optional.of(EncryptionAlgorithm.AES_GCM_256));
        header.setAlgorithm(Algorithm.DIRECT);

        JWE jwe = new JWE();
        jwe.setHeader(header);
        jwe.setCek(decoder.decode(key.getKey()));
        jwe.setPayload("Help me, Obi-Wan Kenobi. You're my only hope.".getBytes());

        byte[] actual = subject.JWEToCompact(jwe);
        assertThat(actual, is(notNullValue()));

        String compactJWE = new String(actual, StandardCharsets.UTF_8);

        String[] jweParts = compactJWE.split("\\.");
        String protectedHeader = new String(decoder.decode(jweParts[0]), StandardCharsets.UTF_8);
        String encryptedKey = new String(decoder.decode(jweParts[1]), StandardCharsets.UTF_8);
        String initVector = new String(decoder.decode(jweParts[2]), StandardCharsets.UTF_8);
        String cipherText = new String(decoder.decode(jweParts[3]), StandardCharsets.UTF_8);
        String authenticationTag = new String(decoder.decode(jweParts[4]), StandardCharsets.UTF_8);

        assertThat(protectedHeader, is(notNullValue()));

        assertThat(encryptedKey, is(notNullValue()));
        assertThat(encryptedKey, is(""));

        assertThat(initVector, is(notNullValue()));
        assertThat(cipherText, is(notNullValue()));
        assertThat(authenticationTag, is(notNullValue()));

        // should be able to deserialize it.
        JweDeserializer jweDeserializer = jwtAppFactory.jweDirectDesializer();

        JWE leia = jweDeserializer.stringToJWE(compactJWE, key);

        assertThat(leia, CoreMatchers.is(CoreMatchers.notNullValue()));
        String payload = new String(leia.getPayload());
        assertThat(payload, CoreMatchers.is("Help me, Obi-Wan Kenobi. You're my only hope."));
    }
}