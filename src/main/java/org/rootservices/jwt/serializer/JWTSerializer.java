package org.rootservices.jwt.serializer;

import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.serializer.exception.InvalidJwtException;

/**
 * Created by tommackenzie on 8/12/15.
 */
public interface JWTSerializer {
    String jwtToString(JsonWebToken jwt) throws InvalidJwtException;
    JsonWebToken stringToJwt(String jwt, Class claimClass) throws InvalidJwtException;
}
