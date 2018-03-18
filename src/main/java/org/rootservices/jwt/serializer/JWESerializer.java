package org.rootservices.jwt.serializer;

import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.jwk.KeyAlgorithm;
import org.rootservices.jwt.serializer.exception.JsonException;
import org.rootservices.jwt.serializer.exception.JsonToJwtException;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JWESerializer {
    public static final String JWT_SPLITTER = "\\.";
    private Serializer serializer;
    private Base64.Encoder encoder;
    private Base64.Decoder decoder;
    private Cipher RSADecryptCipher;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JWESerializer(Serializer serializer, Base64.Encoder encoder, Base64.Decoder decoder, Cipher RSADecryptCipher, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serializer = serializer;
        this.encoder = encoder;
        this.decoder = decoder;
        this.RSADecryptCipher = RSADecryptCipher;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    public JWE<ByteArrayInputStream> stringToJWE(String compactJWE) throws JsonToJwtException, Exception {
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
            throw new JsonToJwtException("JWT json is invalid", e);
        }

        byte[] cek = null;
        try {
            cek = RSADecryptCipher.doFinal(encryptedKey);
        } catch (IllegalBlockSizeException e) {
            throw e;
        } catch (BadPaddingException e) {
            throw e;
        }

        byte[] aad = jweParts[0].getBytes(StandardCharsets.US_ASCII);

        Cipher symmetricCipher = symmetricCipher(cek, initVector, aad);
        byte[] cipherTextWithAuthTag = cipherTextWithAuthTag(cipherText, authenticationTag);

        byte[] text;
        try {
            text = symmetricCipher.doFinal(cipherTextWithAuthTag);
        } catch (IllegalBlockSizeException e) {
            throw e;
        } catch (BadPaddingException e) {
            throw e;
        }

        ByteArrayInputStream payload = new ByteArrayInputStream(text);
        return new JWE<ByteArrayInputStream>(header, payload, cek, initVector, authenticationTag);
    }


    // The symmetric cipher should not be a dependency b/c it cannot be re-used.
    // init vectors are different per JWE.
    // it maybe injected in for plain old AES not GCM.
    protected Cipher symmetricCipher(byte[] cek, byte[] iv, byte[] aad) {
        SecretKey key = new SecretKeySpec(cek, KeyAlgorithm.AES.getValue());
        Cipher cipher = null;
        try {
            cipher = cipherSymmetricFactory.forDecrypt(Transformation.AES_GCM_NO_PADDING, key, iv, aad);
        } catch (CipherException e) {
            // TODO: throw an exception.
        }

        return cipher;
    }

    protected byte[] cipherTextWithAuthTag(byte[] cipherText, byte[] authTag) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        try {
            outputStream.write(cipherText);
            outputStream.write(authTag);
        } catch (IOException e) {
            // TODO: throw an exception.
        }

        return outputStream.toByteArray();
    }
}
