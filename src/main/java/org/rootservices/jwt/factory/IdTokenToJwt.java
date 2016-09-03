package org.rootservices.jwt.factory;


import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 9/1/16.
 */
public class IdTokenToJwt {

    private SecureJwtFactory secureJwtFactory;
    private JWTSerializer jwtSerializer;
    // TODO: push injection of ^ to app factory.


    public IdTokenToJwt(SecureJwtFactory secureJwtFactory, JWTSerializer jwtSerializer) {
        this.secureJwtFactory = secureJwtFactory;
        this.jwtSerializer = jwtSerializer;
    }

    public String makeSecureJwt(Claims claims) throws JwtToJsonException {

        JsonWebToken jsonWebToken = null;
        try {
            jsonWebToken = secureJwtFactory.makeJwt(claims);
        } catch (JwtToJsonException e) {
            throw e;
        }

        String jwt = null;
        try {
            jwt = jwtSerializer.jwtToString(jsonWebToken);
        } catch (JwtToJsonException e) {
            throw e;
        }

        return jwt;

    }
}
