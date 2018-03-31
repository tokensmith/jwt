package org.rootservices.jwt.jwe.serialization;

import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.serialization.exception.EncryptException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public interface JweSerializer {
    byte[] DELIMITER = ".".getBytes();
    String COULD_NOT_COMPACT = "Could not compact";
    byte[] JWEToCompact(JWE jwe) throws JsonToJwtException, CipherException, EncryptException;

    default byte[] extractCipherText(byte[] cipherTextWithAuthTag) {
        int tagLength = CipherSymmetricFactory.GCM_TAG_LENGTH / Byte.SIZE;
        int cipherTextEnd = cipherTextWithAuthTag.length - tagLength;

        byte[] cipherText = new byte[cipherTextEnd];
        System.arraycopy(cipherTextWithAuthTag, 0, cipherText, 0, cipherTextEnd);
        return cipherText;
    }

    default byte[] extractAuthTag(byte[] cipherTextWithAuthTag) {
        int tagLength = CipherSymmetricFactory.GCM_TAG_LENGTH / Byte.SIZE;
        int cipherTextEnd = cipherTextWithAuthTag.length - tagLength;

        byte[] authTag = new byte[tagLength];
        System.arraycopy(cipherTextWithAuthTag, cipherTextEnd, authTag, 0, tagLength);
        return authTag;
    }

    default byte[] toCompact(List<byte[]> jweParts) throws EncryptException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );

        for(int i=0; i < jweParts.size(); i++) {
            if (jweParts.get(i) != null) {
                try {
                    outputStream.write(jweParts.get(i));
                } catch (IOException e) {
                    throw new EncryptException(COULD_NOT_COMPACT, e);
                }
            }

            if (i < jweParts.size() - 1) {
                try {
                    outputStream.write(DELIMITER);
                } catch (IOException e) {
                    throw new EncryptException(COULD_NOT_COMPACT, e);
                }
            }
        }

        return outputStream.toByteArray();
    }
}
