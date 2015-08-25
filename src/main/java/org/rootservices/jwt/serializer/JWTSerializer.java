package org.rootservices.jwt.serializer;

import org.rootservices.jwt.entity.jwt.Token;

/**
 * Created by tommackenzie on 8/12/15.
 */
public interface JWTSerializer {
    String tokenToJwt(Token token);
    Token jwtToToken(String jwt, Class claimClass);
}
