package net.tokensmith.jwt.jwe.serialization.rsa;

import net.tokensmith.jwt.jwe.Transformation;
import net.tokensmith.jwt.jwe.entity.JWE;
import net.tokensmith.jwt.jwe.factory.CipherSymmetricFactory;
import net.tokensmith.jwt.jwe.factory.exception.CipherException;
import net.tokensmith.jwt.jwe.serialization.JweSerializer;
import net.tokensmith.jwt.serialization.Serdes;
import net.tokensmith.jwt.serialization.exception.EncryptException;
import net.tokensmith.jwt.serialization.exception.JsonException;
import net.tokensmith.jwt.serialization.exception.JsonToJwtException;
import net.tokensmith.jwt.jwk.KeyAlgorithm;
import net.tokensmith.jwt.jwk.generator.jdk.SecretKeyGenerator;
import net.tokensmith.jwt.jwk.exception.SecretKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class JweRsaSerializer implements JweSerializer {
    public static final String COULD_NOT_ENCRYPT_CEK = "Could not encrypt Content Encryption Key";
    public static final String COULD_NOT_ENCRYPT = "Could not encrypt content";
    public static final String HEADER_IS_INVALID = "Header is invalid. Could not serialize to it to JSON";
    public static final String FAILED_TO_CREATE_CONTENT_ENCRYPTION_KEY = "Failed to create Content Encryption Key";
    private Serdes serdes;
    private Base64.Encoder encoder;
    private Cipher RSAEncryptCipher;
    private SecretKeyGenerator secretKeyGenerator;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JweRsaSerializer(Serdes serdes, Base64.Encoder encoder, Cipher RSAEncryptCipher, SecretKeyGenerator secretKeyGenerator, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serdes = serdes;
        this.encoder = encoder;
        this.RSAEncryptCipher = RSAEncryptCipher;
        this.secretKeyGenerator = secretKeyGenerator;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    public ByteArrayOutputStream JWEToCompact(JWE jwe) throws JsonToJwtException, CipherException, EncryptException {

        byte[] protectedHeader;
        try {
            protectedHeader = serdes.objectToByte(jwe.getHeader());
        } catch (JsonException e) {
            throw new JsonToJwtException(HEADER_IS_INVALID, e);
        }

        byte[] aad = encoder.encode(protectedHeader);


        SecretKey cek;
        try {
            cek = secretKeyGenerator.makeKey(KeyAlgorithm.AES);
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
        jweParts.add(encoder.encode(protectedHeader));
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
