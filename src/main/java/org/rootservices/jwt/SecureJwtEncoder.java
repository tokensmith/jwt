package org.rootservices.jwt;


import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.factory.SecureJwtFactory;
import org.rootservices.jwt.factory.UnSecureJwtFactory;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 9/1/16.
 */
public class SecureJwtEncoder {
    private SecureJwtFactory secureJwtFactory;
    private JWTSerializer jwtSerializer;

    public SecureJwtEncoder(SecureJwtFactory secureJwtFactory, JWTSerializer jwtSerializer) {
        this.secureJwtFactory = secureJwtFactory;
        this.jwtSerializer = jwtSerializer;
    }

    public String encode(Claims claims) throws JwtToJsonException {

        JsonWebToken jsonWebToken = null;
        try {
            jsonWebToken = secureJwtFactory.makeJwt(claims);
        } catch (JwtToJsonException e) {
            throw e;
        }

        String jwt;
        try {
            jwt = jwtSerializer.jwtToString(jsonWebToken);
        } catch (JwtToJsonException e) {
            throw e;
        }

        return jwt;
    }
}
