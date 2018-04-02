package org.rootservices.jwt.jwe.serialization.direct;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.jwe.serialization.JweDeserializer;
import org.rootservices.jwt.serialization.Serdes;
import org.rootservices.jwt.serialization.exception.DecryptException;
import org.rootservices.jwt.serialization.exception.JsonException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class JweDirectDesializer implements JweDeserializer {
    private Serdes serdes;
    private Base64.Decoder decoder;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JweDirectDesializer(Serdes serdes, Base64.Decoder decoder, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serdes = serdes;
        this.decoder = decoder;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    @Override
    public JWE stringToJWE(String compactJWE, Key key) throws JsonToJwtException, DecryptException, CipherException {
        String[] jweParts = compactJWE.split(JWT_SPLITTER);
        byte[] protectedHeader = decoder.decode(jweParts[0]);
        byte[] initVector = decoder.decode(jweParts[2]);
        byte[] cipherText = decoder.decode(jweParts[3]);
        byte[] authenticationTag = decoder.decode(jweParts[4]);

        Header header;
        try {
            header = (Header) serdes.jsonBytesToObject(protectedHeader, Header.class);
        } catch (JsonException e) {
            throw new JsonToJwtException(COMPACT_JWE_INVALID, e);
        }

        byte[] aad = jweParts[0].getBytes(StandardCharsets.US_ASCII);

        byte[] cek = decoder.decode(((SymmetricKey) key).getKey().getBytes());
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
