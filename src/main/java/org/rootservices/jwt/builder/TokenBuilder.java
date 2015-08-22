package org.rootservices.jwt.builder;

import org.rootservices.jwt.entity.jwt.RegisteredClaimNames;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.Algorithm;

import java.util.Optional;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class TokenBuilder {

    /**
     * Build a unsecure JWT.
     *
     * Unsecure JWTs have a header algorithm value of "none" and
     * a empty signature.
     *
     * @param claimNames
     * @return
     */
    public Token makeUnsecuredToken(RegisteredClaimNames claimNames) {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        Token token = new Token();
        token.setHeader(header);
        token.setClaimNames(claimNames);
        token.setSignature(Optional.<String>empty());

        return token;
    };
}
