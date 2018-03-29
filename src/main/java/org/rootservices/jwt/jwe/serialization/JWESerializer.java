package org.rootservices.jwt.jwe.serialization;

import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class JWESerializer {
    public static final String COULD_NOT_ENCRYPT_CEK = "Could not encrypt Content Encryption Key";
    public static final String COULD_NOT_ENCRYPT = "Could not encrypt content";
    public static final String HEADER_IS_INVALID = "Header is invalid. Could not serialize to it to JSON";
    public static final String COULD_NOT_COMPACT = "Could not compact";
    public static final String FAILED_TO_CREATE_CONTENT_ENCRYPTION_KEY = "Failed to create Content Encryption Key";
    private Serializer serializer;
    private Base64.Encoder encoder;
    private Cipher RSAEncryptCipher;
    private SecretKeyFactory secretKeyFactory;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JWESerializer(Serializer serializer, Base64.Encoder encoder, Cipher RSAEncryptCipher, SecretKeyFactory secretKeyFactory, CipherSymmetricFactory cipherSymmetricFactory) {
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

    protected byte[] extractCipherText(byte[] cipherTextWithAuthTag) {
        int tagLength = CipherSymmetricFactory.GCM_TAG_LENGTH / Byte.SIZE;
        int cipherTextEnd = cipherTextWithAuthTag.length - tagLength;

        byte[] cipherText = new byte[cipherTextEnd];
        System.arraycopy(cipherTextWithAuthTag, 0, cipherText, 0, cipherTextEnd);
        return cipherText;
    }

    protected byte[] extractAuthTag(byte[] cipherTextWithAuthTag) {
        int tagLength = CipherSymmetricFactory.GCM_TAG_LENGTH / Byte.SIZE;
        int cipherTextEnd = cipherTextWithAuthTag.length - tagLength;

        byte[] authTag = new byte[tagLength];
        System.arraycopy(cipherTextWithAuthTag, cipherTextEnd, authTag, 0, tagLength);
        return authTag;
    }

    protected byte[] toCompact(List<byte[]> jweParts) throws EncryptException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        byte[] delimitter = ".".getBytes();

        for(int i=0; i < jweParts.size(); i++) {

            try {
                outputStream.write(jweParts.get(i));
            } catch (IOException e) {
                throw new EncryptException(COULD_NOT_COMPACT, e);
            }

            if (i < jweParts.size() - 1) {
                try {
                    outputStream.write(delimitter);
                } catch (IOException e) {
                    throw new EncryptException(COULD_NOT_COMPACT, e);
                }
            }
        }

        return outputStream.toByteArray();
    }
}
