package net.tokensmith.jwt.builder.compact;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwe.EncryptionAlgorithm;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import org.hamcrest.CoreMatchers;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jwe.entity.JWE;
import net.tokensmith.jwt.jwe.serialization.JweDeserializer;
import net.tokensmith.jwt.jwe.serialization.rsa.JweRsaDeserializer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.*;

public class EncryptedCompactBuilderTest {
    private static JwtAppFactory jwtAppFactory = new JwtAppFactory();
    private EncryptedCompactBuilder subject;

    @Before
    public void setUp() {
        subject = new EncryptedCompactBuilder();
    }

    @Test
    public void buildWithDirect() throws Exception {

        SymmetricKey key = Factory.makeSymmetricKeyForJWE();

        byte[] payload = "Help me, Obi-Wan Kenobi. You're my only hope.".getBytes();

        ByteArrayOutputStream actual = subject.encAlg(EncryptionAlgorithm.AES_GCM_256)
                .alg(Algorithm.DIRECT)
                .encAlg(EncryptionAlgorithm.AES_GCM_256)
                .payload(payload)
                .cek(key)
                .build();

        assertThat(actual, is(notNullValue()));

        String compactJWE = actual.toString();

        Base64.Decoder decoder = jwtAppFactory.urlDecoder();

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
        String decryptedPayload = new String(leia.getPayload());
        assertThat(decryptedPayload, CoreMatchers.is("Help me, Obi-Wan Kenobi. You're my only hope."));
    }

    @Test
    public void buildWithRSA() throws Exception {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();

        byte[] payload = "Help me, Obi-Wan Kenobi. You're my only hope.".getBytes();

        RSAPublicKey publicKey = Factory.makeRSAPublicKeyForJWE();
        publicKey.setKeyId(Optional.of(UUID.randomUUID().toString()));

        ByteArrayOutputStream actual = subject.encAlg(EncryptionAlgorithm.AES_GCM_256)
                .alg(Algorithm.RSAES_OAEP)
                .payload(payload)
                .rsa(publicKey)
                .build();

        // make sure it can be read.
        RSAKeyPair jwk = Factory.makeRSAKeyPairForJWE();
        JweRsaDeserializer JweRsaDeserializer = jwtAppFactory.jweRsaDeserializer();

        String compactJWE = actual.toString();

        JWE leia = JweRsaDeserializer.stringToJWE(compactJWE, jwk);

        assertThat(leia, CoreMatchers.is(CoreMatchers.notNullValue()));
        String decryptedPayload = new String(leia.getPayload());
        assertThat(decryptedPayload, CoreMatchers.is("Help me, Obi-Wan Kenobi. You're my only hope."));

    }

}