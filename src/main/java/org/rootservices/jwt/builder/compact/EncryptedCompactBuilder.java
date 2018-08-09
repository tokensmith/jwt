package org.rootservices.jwt.builder.compact;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.rootservices.jwt.builder.exception.CompactException;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.jwe.serialization.JweSerializer;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import org.rootservices.jwt.serialization.exception.EncryptException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import java.io.ByteArrayOutputStream;

public class EncryptedCompactBuilder {
    private static final Logger LOGGER = LogManager.getLogger(EncryptedCompactBuilder.class);
    public static final String UNABLE_TO_BUILD_COMPACT_JWE = "Unable to build compact jwe";
    private static JwtAppFactory jwtAppFactory = new JwtAppFactory();

    private JWE jwe;
    private RSAPublicKey publicKey;

    public EncryptedCompactBuilder jwe(JWE jwe) {
        this.jwe = jwe;
        return this;
    }

    public EncryptedCompactBuilder key(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public ByteArrayOutputStream build() throws CompactException {
        JweSerializer jweSerializer;
        if (publicKey != null) {
            try {
                jweSerializer = jwtAppFactory.jweRsaSerializer(publicKey);
            } catch (PublicKeyException | CipherException e) {
                LOGGER.error(e.getMessage(), e);
                throw new CompactException(UNABLE_TO_BUILD_COMPACT_JWE, e);
            }
        } else {
            jweSerializer = jwtAppFactory.jweDirectSerializer();
        }

        try {
            return jweSerializer.JWEToCompact(jwe);
        } catch (JsonToJwtException | CipherException | EncryptException e) {
            LOGGER.error(e.getMessage(), e);
            throw new CompactException(UNABLE_TO_BUILD_COMPACT_JWE, e);
        }
    }

}
