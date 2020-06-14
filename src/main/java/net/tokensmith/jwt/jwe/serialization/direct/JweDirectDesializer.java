package net.tokensmith.jwt.jwe.serialization.direct;

import net.tokensmith.jwt.entity.jwk.Key;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Header;
import net.tokensmith.jwt.jwe.Transformation;
import net.tokensmith.jwt.jwe.entity.JWE;
import net.tokensmith.jwt.jwe.factory.CipherSymmetricFactory;
import net.tokensmith.jwt.jwe.factory.exception.CipherException;
import net.tokensmith.jwt.serialization.Serdes;
import net.tokensmith.jwt.serialization.exception.DecryptException;
import net.tokensmith.jwt.serialization.exception.JsonException;
import net.tokensmith.jwt.serialization.exception.JsonToJwtException;
import net.tokensmith.jwt.jwe.serialization.JweDeserializer;
import net.tokensmith.jwt.jwe.serialization.exception.KeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class JweDirectDesializer implements JweDeserializer {
    public static final String KEY_CANNOT_BE_DECODED = "Key cannot be decoded.";
    private Serdes serdes;
    private Base64.Decoder decoder;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JweDirectDesializer(Serdes serdes, Base64.Decoder decoder, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serdes = serdes;
        this.decoder = decoder;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    @Override
    public JWE stringToJWE(String compactJWE, Key key) throws JsonToJwtException, DecryptException, CipherException, KeyException {
        String[] jweParts = compactJWE.split(JWT_SPLITTER);
        byte[] protectedHeader = decoder.decode(jweParts[0]);
        byte[] initVector = decoder.decode(jweParts[2]);
        byte[] cipherText = decoder.decode(jweParts[3]);
        byte[] authenticationTag = decoder.decode(jweParts[4]);

        Header header;
        try {
            header = serdes.jsonBytesTo(protectedHeader, Header.class);
        } catch (JsonException e) {
            throw new JsonToJwtException(COMPACT_JWE_INVALID, e);
        }

        byte[] aad = jweParts[0].getBytes(StandardCharsets.US_ASCII);

        byte[] cek;
        try {
            cek = decoder.decode(((SymmetricKey) key).getKey().getBytes());
        } catch (IllegalArgumentException e) {
            throw new KeyException(KEY_CANNOT_BE_DECODED, e);
        }

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
