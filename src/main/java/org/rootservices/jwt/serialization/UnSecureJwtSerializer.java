package org.rootservices.jwt.serialization;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.factory.UnSecureJwtFactory;
import org.rootservices.jwt.serialization.JWTDeserializer;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 7/12/16.
 */
public class UnSecureJwtSerializer {
    private UnSecureJwtFactory unSecureJwtFactory;
    private JWTDeserializer jwtDeserializer;

    public UnSecureJwtSerializer(UnSecureJwtFactory unSecureJwtFactory, JWTDeserializer jwtDeserializer) {
        this.unSecureJwtFactory = unSecureJwtFactory;
        this.jwtDeserializer = jwtDeserializer;
    }

    public String encode(Claims claims) {

        JsonWebToken jsonWebToken = unSecureJwtFactory.makeJwt(claims);

        String encodedJwt = null;
        try {
            encodedJwt = jwtDeserializer.jwtToString(jsonWebToken);
        } catch (JwtToJsonException e) {
            e.printStackTrace();
        }

        return encodedJwt;
    }
}
