package net.tokensmith.jwt.jwe.serialization.direct;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwe.EncryptionAlgorithm;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.Header;
import org.hamcrest.CoreMatchers;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jwe.entity.JWE;
import net.tokensmith.jwt.jwe.serialization.JweDeserializer;
import net.tokensmith.jwt.jwe.serialization.JweSerializer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;


public class JweDirectSerializerTest {
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

        ByteArrayOutputStream actual = subject.JWEToCompact(jwe);
        assertThat(actual, is(notNullValue()));

        String compactJWE = actual.toString();

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