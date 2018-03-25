package org.rootservices.jwt.encoder;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.factory.UnSecureJwtFactory;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 7/12/16.
 */
public class UnSecureJwtEncoder {
    private UnSecureJwtFactory unSecureJwtFactory;
    private JWTSerializer jwtSerializer;

    public UnSecureJwtEncoder(UnSecureJwtFactory unSecureJwtFactory, JWTSerializer jwtSerializer) {
        this.unSecureJwtFactory = unSecureJwtFactory;
        this.jwtSerializer = jwtSerializer;
    }

    public String encode(Claims claims) {

        JsonWebToken jsonWebToken = unSecureJwtFactory.makeJwt(claims);

        String encodedJwt = null;
        try {
            encodedJwt = jwtSerializer.jwtToString(jsonWebToken);
        } catch (JwtToJsonException e) {
            e.printStackTrace();
        }

        return encodedJwt;
    }
}
