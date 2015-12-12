package org.rootservices.jwt.serializer;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.serializer.exception.JsonToJwtException;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 8/12/15.
 */
public interface JWTSerializer {
    String jwtToString(JsonWebToken jwt) throws JwtToJsonException;
    String makeSignInput(Header header, Claims claims) throws JwtToJsonException;
    JsonWebToken stringToJwt(String jwt, Class claimClass) throws JsonToJwtException;
}
