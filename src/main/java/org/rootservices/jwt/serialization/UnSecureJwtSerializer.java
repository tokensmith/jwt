package org.rootservices.jwt.serialization;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.factory.UnSecureJwtFactory;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 7/12/16.
 */
public class UnSecureJwtSerializer {
    private UnSecureJwtFactory unSecureJwtFactory;
    private JwtSerde jwtSerde;

    public UnSecureJwtSerializer(UnSecureJwtFactory unSecureJwtFactory, JwtSerde jwtSerde) {
        this.unSecureJwtFactory = unSecureJwtFactory;
        this.jwtSerde = jwtSerde;
    }

    public String compactJWT(Claims claims) {

        JsonWebToken jsonWebToken = unSecureJwtFactory.makeJwt(claims);

        String encodedJwt = null;
        try {
            encodedJwt = jwtSerde.compactJwt(jsonWebToken);
        } catch (JwtToJsonException e) {
            e.printStackTrace();
        }

        return encodedJwt;
    }
}
