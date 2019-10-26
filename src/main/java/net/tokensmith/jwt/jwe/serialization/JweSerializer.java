package net.tokensmith.jwt.jwe.serialization;

import net.tokensmith.jwt.jwe.entity.JWE;
import net.tokensmith.jwt.jwe.factory.CipherSymmetricFactory;
import net.tokensmith.jwt.jwe.factory.exception.CipherException;
import net.tokensmith.jwt.serialization.exception.EncryptException;
import net.tokensmith.jwt.serialization.exception.JsonToJwtException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public interface JweSerializer {
    byte[] DELIMITER = ".".getBytes();
    String COULD_NOT_COMPACT = "Could not compact";
    ByteArrayOutputStream JWEToCompact(JWE jwe) throws JsonToJwtException, CipherException, EncryptException;

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

    default ByteArrayOutputStream toCompact(List<byte[]> jweParts) throws EncryptException {
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

        return outputStream;
    }
}
