package org.rootservices.jwt.builder.compact;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.rootservices.jwt.builder.exception.CompactException;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.exception.SignatureException;
import org.rootservices.jwt.jws.serialization.SecureJwtSerializer;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

import java.io.ByteArrayOutputStream;

public class SecureCompactBuilder {
    private static final Logger LOGGER = LogManager.getLogger(SecureCompactBuilder.class);
    public static final String UNABLE_TO_BUILD_COMPACT_JWT = "Unable to build compact jwt";
    private static JwtAppFactory jwtAppFactory = new JwtAppFactory();

    private Claims claims;
    private Key key;
    private Algorithm alg;

    public SecureCompactBuilder claims(Claims claims) {
        this.claims = claims;
        return this;
    }

    public SecureCompactBuilder key(Key key) {
        this.key = key;
        return this;
    }

    public SecureCompactBuilder alg(Algorithm alg) {
        this.alg = alg;
        return this;
    }


    public ByteArrayOutputStream build() throws CompactException {
        SecureJwtSerializer secureJwtSerializer;
        try {
            secureJwtSerializer = jwtAppFactory.secureJwtSerializer(alg, key);
        } catch (SignatureException e) {
            LOGGER.error(e.getMessage(), e);
            throw new CompactException(UNABLE_TO_BUILD_COMPACT_JWT, e);
        }

        try {
            return secureJwtSerializer.compactJwt(claims);
        } catch (JwtToJsonException e) {
            LOGGER.error(e.getMessage(), e);
            throw new CompactException(UNABLE_TO_BUILD_COMPACT_JWT, e);
        }
    }
}
