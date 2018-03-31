package org.rootservices.jwt.jwe.serialization.rsa;

import helper.entity.Factory;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwe.EncryptionAlgorithm;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.jwe.entity.JWE;


import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;

public class JweRsaSerializerTest {

    @Test
    public void extractCipherText() throws Exception {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        Base64.Decoder decoder = jwtAppFactory.urlDecoder();
        String compactJWE = Factory.compactJWE();

        String[] jweParts = compactJWE.split(JweRsaDeserializer.JWT_SPLITTER);
        byte[] protectedHeader = decoder.decode(jweParts[0]);
        byte[] encryptedKey = decoder.decode(jweParts[1]);
        byte[] initVector = decoder.decode(jweParts[2]);
        byte[] cipherText = decoder.decode(jweParts[3]);
        byte[] authenticationTag = decoder.decode(jweParts[4]);

        RSAKeyPair jwk = Factory.makeRSAKeyPairForJWE();
        JweRsaDeserializer JweRsaDeserializer = jwtAppFactory.jweRsaDeserializer();

        RSAPublicKey publicKey = Factory.makeRSAPublicKeyForJWE();
        JweRsaSerializer subject = jwtAppFactory.jweRsaSerializer(publicKey);

        byte[] cipherTextWithAuthTag = JweRsaDeserializer.cipherTextWithAuthTag(cipherText, authenticationTag);

        assertThat(cipherTextWithAuthTag.length, is(cipherText.length + authenticationTag.length));

        byte[] actual = subject.extractCipherText(cipherTextWithAuthTag);
        assertThat(actual.length, is(cipherText.length));
        assertThat(actual, is(cipherText));
    }

    @Test
    public void extractAuthTag() throws Exception {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        Base64.Decoder decoder = jwtAppFactory.urlDecoder();
        String compactJWE = Factory.compactJWE();

        String[] jweParts = compactJWE.split(JweRsaDeserializer.JWT_SPLITTER);
        byte[] protectedHeader = decoder.decode(jweParts[0]);
        byte[] encryptedKey = decoder.decode(jweParts[1]);
        byte[] initVector = decoder.decode(jweParts[2]);
        byte[] cipherText = decoder.decode(jweParts[3]);
        byte[] authenticationTag = decoder.decode(jweParts[4]);


        RSAKeyPair jwk = Factory.makeRSAKeyPairForJWE();
        JweRsaDeserializer JweRsaDeserializer = jwtAppFactory.jweRsaDeserializer();

        RSAPublicKey publicKey = Factory.makeRSAPublicKeyForJWE();
        JweRsaSerializer subject = jwtAppFactory.jweRsaSerializer(publicKey);

        byte[] cipherTextWithAuthTag = JweRsaDeserializer.cipherTextWithAuthTag(cipherText, authenticationTag);

        assertThat(cipherTextWithAuthTag.length, is(cipherText.length + authenticationTag.length));

        byte[] actual = subject.extractAuthTag(cipherTextWithAuthTag);
        assertThat(actual.length, is(authenticationTag.length));
        assertThat(actual, is(authenticationTag));
    }

    @Test
    public void JWEToCompact() throws Exception {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();

        RSAPublicKey publicKey = Factory.makeRSAPublicKeyForJWE();
        JweRsaSerializer subject = jwtAppFactory.jweRsaSerializer(publicKey);

        Header header = new Header();
        header.setEncryptionAlgorithm(Optional.of(EncryptionAlgorithm.AES_GCM_256));
        header.setAlgorithm(Algorithm.RSAES_OAEP);

        JWE jwe = new JWE();
        jwe.setHeader(header);
        jwe.setPayload("Help me, Obi-Wan Kenobi. You're my only hope.".getBytes());

        byte[] actual = subject.JWEToCompact(jwe);

        // make sure it can be read.
        RSAKeyPair jwk = Factory.makeRSAKeyPairForJWE();
        JweRsaDeserializer JweRsaDeserializer = jwtAppFactory.jweRsaDeserializer();

        String compactJWE = new String(actual, StandardCharsets.UTF_8);

        JWE leia = JweRsaDeserializer.stringToJWE(compactJWE, jwk);

        assertThat(leia, is(notNullValue()));
        String payload = new String(leia.getPayload());
        assertThat(payload, is("Help me, Obi-Wan Kenobi. You're my only hope."));

    }

}