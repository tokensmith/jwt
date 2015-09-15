package org.rootservices.jwt.builder;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.TokenType;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.signature.signer.Signer;


import java.util.Optional;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class UnsecureTokenBuilder {
    private JWTSerializer jwtSerializer;

    public UnsecureTokenBuilder(JWTSerializer jwtSerializer) {
        this.jwtSerializer = jwtSerializer;
    }
    
    public Token build(Claims claimNames) {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        Token token = new Token();
        token.setHeader(header);
        token.setClaims(claimNames);
        token.setSignature(Optional.<String>empty());

        return token;
    };
}
