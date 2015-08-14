package org.rootservices.jwt.builder;

import org.rootservices.jwt.entity.RegisteredClaimNames;
import org.rootservices.jwt.entity.Token;
import org.rootservices.jwt.entity.header.Header;
import org.rootservices.jwt.entity.header.Algorithm;

import java.util.Optional;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class TokenBuilder {

    /**
     * Build a unsecure JWT.
     *
     * Unsecure JWTs have a header type value of "none" and
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
