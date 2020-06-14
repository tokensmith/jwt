package net.tokensmith.jwt.builder.compact;

import net.tokensmith.jwt.entity.jwk.Key;
import net.tokensmith.jwt.entity.jwt.Claims;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.builder.exception.CompactException;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.exception.SignatureException;
import net.tokensmith.jwt.jws.serialization.SecureJwtSerializer;
import net.tokensmith.jwt.serialization.exception.JwtToJsonException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;

public class SecureCompactBuilder {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecureCompactBuilder.class);
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
