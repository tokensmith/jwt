package org.rootservices.jwt.jwe.serialization.direct;

import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.jwe.serialization.JweSerializer;
import org.rootservices.jwt.jwk.KeyAlgorithm;
import org.rootservices.jwt.serialization.Serializer;
import org.rootservices.jwt.serialization.exception.EncryptException;
import org.rootservices.jwt.serialization.exception.JsonException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class JweDirectSerializer implements JweSerializer {
    public static final String COULD_NOT_ENCRYPT = "Could not encrypt content";
    public static final String HEADER_IS_INVALID = "Header is invalid. Could not serialize to it to JSON";

    private Serializer serializer;
    private Base64.Encoder encoder;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JweDirectSerializer(Serializer serializer, Base64.Encoder encoder, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serializer = serializer;
        this.encoder = encoder;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    /**
     * Generates a compact JWE.
     *
     * Ignores the value for the jwe iv and generates a new one.
     *
     * The variable symmetricCipher is a propagating dependency. I think that is ok b/c it cannot be reused per
     * encryption attempt b/c per encryption attempt it needs to use a new iv and add.
     *
     * @param jwe must have values for header, cek, payload. Ignores the value for iv and generates a new one.
     * @return a byte[] that is a compact JWE
     * @throws JsonToJwtException if the header cannot be serialized.
     * @throws CipherException if the cipher for encryption could not be instantiated
     * @throws EncryptException if the payload could not be encrypted
     */
    @Override
    public byte[] JWEToCompact(JWE jwe) throws JsonToJwtException, CipherException, EncryptException {
        String protectedHeader;
        try {
            protectedHeader = serializer.objectToJson(jwe.getHeader());
        } catch (JsonException e) {
            throw new JsonToJwtException(HEADER_IS_INVALID, e);
        }

        byte[] aad = encoder.encode(protectedHeader.getBytes());

        SecretKey key = new SecretKeySpec(jwe.getCek(), KeyAlgorithm.AES.getValue());

        Cipher symmetricCipher;
        try {
            symmetricCipher = cipherSymmetricFactory.forEncrypt(Transformation.AES_GCM_NO_PADDING, key, aad);
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


        byte[] initVector = symmetricCipher.getIV();
        byte[] cipherText = extractCipherText(cipherTextWithAuthTag);
        byte[] authTag = extractAuthTag(cipherTextWithAuthTag);

        List<byte[]> jweParts = new ArrayList<>();
        jweParts.add(encoder.encode(protectedHeader.getBytes()));
        jweParts.add(null);
        jweParts.add(encoder.encode(initVector));
        jweParts.add(encoder.encode(cipherText));
        jweParts.add(encoder.encode(authTag));

        return toCompact(jweParts);
    }
}