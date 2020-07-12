package net.tokensmith.jwt.jwe.serialization.rsa;

import net.tokensmith.jwt.entity.jwk.Key;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwt.header.Header;
import net.tokensmith.jwt.jwe.Transformation;
import net.tokensmith.jwt.jwe.entity.JWE;
import net.tokensmith.jwt.jwe.factory.CipherRSAFactory;
import net.tokensmith.jwt.jwe.factory.CipherSymmetricFactory;
import net.tokensmith.jwt.jwe.factory.exception.CipherException;
import net.tokensmith.jwt.serialization.Serdes;
import net.tokensmith.jwt.serialization.exception.DecryptException;
import net.tokensmith.jwt.serialization.exception.JsonException;
import net.tokensmith.jwt.serialization.exception.JsonToJwtException;
import net.tokensmith.jwt.jwe.serialization.JweDeserializer;
import net.tokensmith.jwt.jwe.serialization.exception.KeyException;
import net.tokensmith.jwt.jwk.PrivateKeyTranslator;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PrivateKeyException;


import javax.crypto.*;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

public class JweRsaDeserializer implements JweDeserializer {

    private Serdes serdes;
    private Base64.Decoder decoder;
    private PrivateKeyTranslator privateKeyTranslator;
    private CipherRSAFactory cipherRSAFactory;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JweRsaDeserializer(Serdes serdes, Base64.Decoder decoder, PrivateKeyTranslator privateKeyTranslator, CipherRSAFactory cipherRSAFactory, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serdes = serdes;
        this.decoder = decoder;
        this.privateKeyTranslator = privateKeyTranslator;
        this.cipherRSAFactory = cipherRSAFactory;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    public JWE stringToJWE(String compactJWE, Key key) throws JsonToJwtException, DecryptException, CipherException, KeyException {
        String[] jweParts = compactJWE.split(JWT_SPLITTER);
        byte[] protectedHeader = decoder.decode(jweParts[0]);
        byte[] encryptedKey = decoder.decode(jweParts[1]);
        byte[] initVector = decoder.decode(jweParts[2]);
        byte[] cipherText = decoder.decode(jweParts[3]);
        byte[] authenticationTag = decoder.decode(jweParts[4]);

        Header header;
        try {
            header = serdes.jsonBytesTo(protectedHeader, Header.class);
        } catch (JsonException e) {
            throw new JsonToJwtException(COMPACT_JWE_INVALID, e);
        }

        RSAKeyPair keyPair = (RSAKeyPair) key;
        RSAPrivateCrtKey jdkKey;
        try {
            jdkKey = privateKeyTranslator.to(keyPair);
        } catch (PrivateKeyException e) {
            throw new KeyException("", e);
        }

        Cipher rsaDecryptCipher;
        try {
            rsaDecryptCipher = cipherRSAFactory.forDecrypt(Transformation.RSA_OAEP, jdkKey);
        } catch (CipherException e) {
            throw e;
        }

        byte[] cek;
        try {
            cek = rsaDecryptCipher.doFinal(encryptedKey);
        } catch (IllegalBlockSizeException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_ENCRYPTED_KEY, e);
        } catch (BadPaddingException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_ENCRYPTED_KEY, e);
        }

        byte[] aad = jweParts[0].getBytes(StandardCharsets.US_ASCII);

        Cipher symmetricCipher;
        try {
            symmetricCipher = cipherSymmetricFactory.forDecrypt(Transformation.AES_GCM_NO_PADDING, cek, initVector, aad);
        } catch (CipherException e) {
            throw e;
        }

        byte[] cipherTextWithAuthTag = cipherTextWithAuthTag(cipherText, authenticationTag);

        byte[] payload;
        try {
            payload = symmetricCipher.doFinal(cipherTextWithAuthTag);
        } catch (IllegalBlockSizeException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_CIPHER_TEXT, e);
        } catch (BadPaddingException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_CIPHER_TEXT, e);
        }

        return new JWE(header, payload, cek, initVector, authenticationTag);
    }
}
