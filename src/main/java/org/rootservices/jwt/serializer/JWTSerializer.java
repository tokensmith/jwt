package org.rootservices.jwt.serializer;

import org.rootservices.jwt.entity.jwt.JsonWebToken;

/**
 * Created by tommackenzie on 8/12/15.
 */
public interface JWTSerializer {
    String tokenToJwt(JsonWebToken token);
    JsonWebToken jwtToToken(String jwt, Class claimClass);
}
