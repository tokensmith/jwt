package org.rootservices.jwt.jwe.serialization;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.jwe.serialization.exception.KeyException;
import org.rootservices.jwt.serialization.exception.DecryptException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public interface JweDeserializer {
    String JWT_SPLITTER = "\\.";
    String COMPACT_JWE_INVALID = "Compact JWE is invalid";
    String COULD_NOT_DECRYPT_ENCRYPTED_KEY = "Could not Decrypt encrypted key";
    String COULD_NOT_DECRYPT_CIPHER_TEXT = "Could not decrypt cipher text";
    String COULD_NOT_COMBINE_CIPHER_TEXT_AND_AT = "Could not combine cipher text with authentication tag";

    JWE stringToJWE(String compactJWE, Key cek) throws JsonToJwtException, DecryptException, CipherException, KeyException;

    default byte[] cipherTextWithAuthTag(byte[] cipherText, byte[] authTag) throws DecryptException {
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
