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
public class TokenBuilder {
    private JWTSerializer jwtSerializer;
    private Signer signer;


    public TokenBuilder(JWTSerializer jwtSerializer, Signer signer) {
        this.jwtSerializer = jwtSerializer;
        this.signer = signer;
    }
    
    public Token makeUnsecuredToken(Claims claimNames) {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        Token token = new Token();
        token.setHeader(header);
        token.setClaims(claimNames);
        token.setSignature(Optional.<String>empty());

        return token;
    };

    public Token makeSignedToken(Algorithm alg, Claims claimNames) {
        Header header = new Header();
        header.setAlgorithm(alg);
        header.setType(TokenType.JWT);

        Token token = new Token();
        token.setHeader(header);
        token.setClaims(claimNames);

        String signature = signer.run(token);
        token.setSignature(Optional.of(signature));

        return token;
    }
}
