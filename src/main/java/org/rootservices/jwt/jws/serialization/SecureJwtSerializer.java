package org.rootservices.jwt.jws.serialization;


import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.factory.SecureJwtFactory;
import org.rootservices.jwt.serialization.JwtSerde;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

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

    public ByteArrayOutputStream compactJwt(Claims claims) throws JwtToJsonException {
        JsonWebToken jsonWebToken;
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
