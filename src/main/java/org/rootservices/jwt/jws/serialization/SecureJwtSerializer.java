package org.rootservices.jwt.jws.serialization;


import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.factory.SecureJwtFactory;
import org.rootservices.jwt.serialization.JwtSerde;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 9/1/16.
 */
public class SecureJwtSerializer {
    private SecureJwtFactory secureJwtFactory;
    private JwtSerde jwtSerde;

    public SecureJwtSerializer(SecureJwtFactory secureJwtFactory, JwtSerde jwtSerde) {
        this.secureJwtFactory = secureJwtFactory;
        this.jwtSerde = jwtSerde;
    }

    public String compactJWT(Claims claims) throws JwtToJsonException {

        JsonWebToken jsonWebToken;
        try {
            jsonWebToken = secureJwtFactory.makeJwt(claims);
        } catch (JwtToJsonException e) {
            throw e;
        }

        String jwt;
        try {
            jwt = jwtSerde.compactJwt(jsonWebToken);
        } catch (JwtToJsonException e) {
            throw e;
        }

        return jwt;
    }
}
