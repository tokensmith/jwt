package org.rootservices.jwt.jwe.serialization.rsa;

import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.jwe.serialization.JweSerializer;
import org.rootservices.jwt.jwk.KeyAlgorithm;
import org.rootservices.jwt.jwk.SecretKeyFactory;
import org.rootservices.jwt.jwk.exception.SecretKeyException;
import org.rootservices.jwt.serialization.Serializer;
import org.rootservices.jwt.serialization.exception.EncryptException;
import org.rootservices.jwt.serialization.exception.JsonException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class JweRsaSerializer implements JweSerializer {
    public static final String COULD_NOT_ENCRYPT_CEK = "Could not encrypt Content Encryption Key";
    public static final String COULD_NOT_ENCRYPT = "Could not encrypt content";
    public static final String HEADER_IS_INVALID = "Header is invalid. Could not serialize to it to JSON";
    public static final String FAILED_TO_CREATE_CONTENT_ENCRYPTION_KEY = "Failed to create Content Encryption Key";
    private Serializer serializer;
    private Base64.Encoder encoder;
    private Cipher RSAEncryptCipher;
    private SecretKeyFactory secretKeyFactory;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JweRsaSerializer(Serializer serializer, Base64.Encoder encoder, Cipher RSAEncryptCipher, SecretKeyFactory secretKeyFactory, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serializer = serializer;
        this.encoder = encoder;
        this.RSAEncryptCipher = RSAEncryptCipher;
        this.secretKeyFactory = secretKeyFactory;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    public byte[] JWEToCompact(JWE jwe) throws JsonToJwtException, CipherException, EncryptException {

        String protectedHeader;
        try {
            protectedHeader = serializer.objectToJson(jwe.getHeader());
        } catch (JsonException e) {
            throw new JsonToJwtException(HEADER_IS_INVALID, e);
        }

        byte[] aad = encoder.encode(protectedHeader.getBytes());


        SecretKey cek;
        try {
            cek = secretKeyFactory.makeKey(KeyAlgorithm.AES);
        } catch (SecretKeyException e) {
            throw new EncryptException(FAILED_TO_CREATE_CONTENT_ENCRYPTION_KEY, e);
        }

        Cipher symmetricCipher;
        try {
            symmetricCipher = symmetricCipherForEncrypt(cek, aad);
        } catch (CipherException e) {
            throw e;
        }

        byte[] cipherTextWithAuthTag;
        try {
            cipherTextWithAuthTag = symmetricCipher.doFinal(jwe.getPayload());
        } catch (IllegalBlockSizeException e) {
            throw new EncryptException(COULD_NOT_ENCRYPT, e);
        } catch (BadPaddingException e) {
            throw new EncryptException(COULD_NOT_ENCRYPT, e);
        }

        byte[] encryptedKey;
        try {
            encryptedKey = RSAEncryptCipher.doFinal(cek.getEncoded());
        } catch (IllegalBlockSizeException e) {
            throw new EncryptException(COULD_NOT_ENCRYPT_CEK, e);
        } catch (BadPaddingException e) {
            throw new EncryptException(COULD_NOT_ENCRYPT_CEK, e);
        }

        byte[] initVector = symmetricCipher.getIV();
        byte[] cipherText = extractCipherText(cipherTextWithAuthTag);
        byte[] authTag = extractAuthTag(cipherTextWithAuthTag);

        List<byte[]> jweParts = new ArrayList<>();
        jweParts.add(encoder.encode(protectedHeader.getBytes()));
        jweParts.add(encoder.encode(encryptedKey));
        jweParts.add(encoder.encode(initVector));
        jweParts.add(encoder.encode(cipherText));
        jweParts.add(encoder.encode(authTag));

        return toCompact(jweParts);
    }

    protected Cipher symmetricCipherForEncrypt(SecretKey cek, byte[] aad) throws CipherException {
        Cipher cipher;
        try {
            cipher = cipherSymmetricFactory.forEncrypt(Transformation.AES_GCM_NO_PADDING, cek, aad);
        } catch (CipherException e) {
            throw e;
        }

        return cipher;
    }
}
