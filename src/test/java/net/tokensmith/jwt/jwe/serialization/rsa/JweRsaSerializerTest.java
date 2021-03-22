package net.tokensmith.jwt.jwe.serialization.rsa;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwe.EncryptionAlgorithm;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.Header;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jwe.entity.JWE;


import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

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

        ByteArrayOutputStream actual = subject.JWEToCompact(jwe);

        // make sure it can be read.
        RSAKeyPair jwk = Factory.makeRSAKeyPairForJWE();
        JweRsaDeserializer JweRsaDeserializer = jwtAppFactory.jweRsaDeserializer();

        String compactJWE = actual.toString();

        JWE leia = JweRsaDeserializer.stringToJWE(compactJWE, jwk);

        assertThat(leia, is(notNullValue()));
        String payload = new String(leia.getPayload());
        assertThat(payload, is("Help me, Obi-Wan Kenobi. You're my only hope."));

    }

}