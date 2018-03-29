package org.rootservices.jwt.jws.serialization;


import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.factory.SecureJwtFactory;
import org.rootservices.jwt.serialization.JWTDeserializer;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 9/1/16.
 */
public class SecureJwtSerializer {
    private SecureJwtFactory secureJwtFactory;
    private JWTDeserializer jwtDeserializer;

    public SecureJwtSerializer(SecureJwtFactory secureJwtFactory, JWTDeserializer jwtDeserializer) {
        this.secureJwtFactory = secureJwtFactory;
        this.jwtDeserializer = jwtDeserializer;
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
            jwt = jwtDeserializer.jwtToString(jsonWebToken);
        } catch (JwtToJsonException e) {
            throw e;
        }

        return jwt;
    }
}
