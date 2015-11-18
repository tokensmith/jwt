package org.rootservices.jwt.builder;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.JWTSerializer;


import java.util.Optional;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class UnsecureJwtBuilder {

    public JsonWebToken build(Claims claimNames) {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        JsonWebToken jwt = new JsonWebToken();
        jwt.setHeader(header);
        jwt.setClaims(claimNames);
        jwt.setSignature(Optional.<String>empty());

        return jwt;
    };
}
