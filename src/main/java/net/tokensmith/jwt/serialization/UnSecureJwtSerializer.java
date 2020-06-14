package net.tokensmith.jwt.serialization;

import net.tokensmith.jwt.entity.jwt.Claims;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.factory.UnSecureJwtFactory;
import net.tokensmith.jwt.serialization.exception.JwtToJsonException;

import java.io.ByteArrayOutputStream;


public class UnSecureJwtSerializer {
    private UnSecureJwtFactory unSecureJwtFactory;
    private JwtSerde jwtSerde;

    public UnSecureJwtSerializer(UnSecureJwtFactory unSecureJwtFactory, JwtSerde jwtSerde) {
        this.unSecureJwtFactory = unSecureJwtFactory;
        this.jwtSerde = jwtSerde;
    }

    public String compactJwtToString(Claims claims) {
        return compactJwt(claims).toString();
    }

    public <T extends Claims> ByteArrayOutputStream compactJwt(T claims) {

        JsonWebToken<T> jsonWebToken = unSecureJwtFactory.makeJwt(claims);

        ByteArrayOutputStream encodedJwt = null;
        try {
            encodedJwt = jwtSerde.compactJwt(jsonWebToken);
        } catch (JwtToJsonException e) {
            e.printStackTrace();
        }

        return encodedJwt;
    }
}
