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
public class UnsecureTokenBuilder {
    private JWTSerializer jwtSerializer;

    public UnsecureTokenBuilder(JWTSerializer jwtSerializer) {
        this.jwtSerializer = jwtSerializer;
    }
    
    public JsonWebToken build(Claims claimNames) {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        JsonWebToken token = new JsonWebToken();
        token.setHeader(header);
        token.setClaims(claimNames);
        token.setSignature(Optional.<String>empty());

        return token;
    };
}
