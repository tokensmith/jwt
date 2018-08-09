package org.rootservices.jwt.builder.compact;

import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.serialization.UnSecureJwtSerializer;

import java.io.ByteArrayOutputStream;

public class UnsecureCompactBuilder {
    private static JwtAppFactory jwtAppFactory = new JwtAppFactory();
    private Claims claims;

    public UnsecureCompactBuilder claims(Claims claims) {
        this.claims = claims;
        return this;
    }

    public ByteArrayOutputStream build() {
        UnSecureJwtSerializer unSecureJwtSerializer = jwtAppFactory.unSecureJwtSerializer();
        return unSecureJwtSerializer.compactJwt(claims);
    }
}
