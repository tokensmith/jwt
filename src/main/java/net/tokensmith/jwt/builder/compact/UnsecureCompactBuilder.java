package net.tokensmith.jwt.builder.compact;

import net.tokensmith.jwt.entity.jwt.Claims;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.serialization.UnSecureJwtSerializer;

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
