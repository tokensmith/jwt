package org.rootservices.jwt.serializer;

import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.jwk.KeyAlgorithm;
import org.rootservices.jwt.jwk.SecretKeyFactory;
import org.rootservices.jwt.serializer.exception.DecryptException;
import org.rootservices.jwt.serializer.exception.EncryptException;
import org.rootservices.jwt.serializer.exception.JsonException;
import org.rootservices.jwt.serializer.exception.JsonToJwtException;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class JWESerializer {
    public static final String JWT_SPLITTER = "\\.";
    public static final String COMPACT_JWE_INVALID = "Compact JWE is invalid";
    public static final String COULD_NOT_DECRYPT_ENCRYPTED_KEY = "Could not Decrypt encrypted key";
    public static final String COULD_NOT_DECRYPT_CIPHER_TEXT = "Could not decrypt cipher text";
    public static final String COULD_NOT_COMBINE_CIPHER_TEXT_AND_AT = "Could not combine cipher text with authentication tag";

    private Serializer serializer;
    private Base64.Decoder decoder;
    private Cipher RSADecryptCipher;
    private SecretKeyFactory secretKeyFactory;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JWESerializer(Serializer serializer, Base64.Decoder decoder, Cipher RSADecryptCipher, SecretKeyFactory secretKeyFactory, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serializer = serializer;
        this.decoder = decoder;
        this.RSADecryptCipher = RSADecryptCipher;
        this.secretKeyFactory = secretKeyFactory;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    public JWE stringToJWE(String compactJWE) throws JsonToJwtException, DecryptException, CipherException {
        String[] jweParts = compactJWE.split(JWT_SPLITTER);
        byte[] protectedHeader = decoder.decode(jweParts[0]);
        byte[] encryptedKey = decoder.decode(jweParts[1]);
        byte[] initVector = decoder.decode(jweParts[2]);
        byte[] cipherText = decoder.decode(jweParts[3]);
        byte[] authenticationTag = decoder.decode(jweParts[4]);

        Header header;
        try {
            header = (Header) serializer.jsonBytesToObject(protectedHeader, Header.class);
        } catch (JsonException e) {
            throw new JsonToJwtException(COMPACT_JWE_INVALID, e);
        }

        byte[] cek;
        try {
            cek = RSADecryptCipher.doFinal(encryptedKey);
        } catch (IllegalBlockSizeException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_ENCRYPTED_KEY, e);
        } catch (BadPaddingException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_ENCRYPTED_KEY, e);
        }

        byte[] aad = jweParts[0].getBytes(StandardCharsets.US_ASCII);

        Cipher symmetricCipher;
        try {
            symmetricCipher = symmetricCipherForDecrypt(cek, initVector, aad);
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

    // The symmetric cipher should not be a dependency b/c it cannot be re-used.
    // init vectors are different per JWE.
    // it maybe injected in for plain old AES not GCM.
    protected Cipher symmetricCipherForDecrypt(byte[] cek, byte[] iv, byte[] aad) throws CipherException {
        SecretKey key = new SecretKeySpec(cek, KeyAlgorithm.AES.getValue());
        Cipher cipher;
        try {
            cipher = cipherSymmetricFactory.forDecrypt(Transformation.AES_GCM_NO_PADDING, key, iv, aad);
        } catch (CipherException e) {
            throw e;
        }

        return cipher;
    }

    public byte[] cipherTextWithAuthTag(byte[] cipherText, byte[] authTag) throws DecryptException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        try {
            outputStream.write(cipherText);
            outputStream.write(authTag);
        } catch (IOException e) {
            throw new DecryptException(COULD_NOT_COMBINE_CIPHER_TEXT_AND_AT, e);
        }

        return outputStream.toByteArray();
    }
}
