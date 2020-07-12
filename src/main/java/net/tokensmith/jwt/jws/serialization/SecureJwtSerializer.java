package net.tokensmith.jwt.jws.serialization;


import net.tokensmith.jwt.entity.jwt.Claims;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.factory.SecureJwtFactory;
import net.tokensmith.jwt.serialization.JwtSerde;
import net.tokensmith.jwt.serialization.exception.JwtToJsonException;

import java.io.ByteArrayOutputStream;


public class SecureJwtSerializer {
    private SecureJwtFactory secureJwtFactory;
    private JwtSerde jwtSerde;

    public SecureJwtSerializer(SecureJwtFactory secureJwtFactory, JwtSerde jwtSerde) {
        this.secureJwtFactory = secureJwtFactory;
        this.jwtSerde = jwtSerde;
    }

    public String compactJwtToString(Claims claims) throws JwtToJsonException {
        return compactJwt(claims).toString();
    }

    public <T extends Claims> ByteArrayOutputStream compactJwt(T claims) throws JwtToJsonException {
        JsonWebToken<T> jsonWebToken;
        try {
            jsonWebToken = secureJwtFactory.makeJwt(claims);
        } catch (JwtToJsonException e) {
            throw e;
        }

        ByteArrayOutputStream compactJwt;
        try {
            compactJwt = jwtSerde.compactJwt(jsonWebToken);
        } catch (JwtToJsonException e) {
            throw e;
        }

        return compactJwt;
    }
}
