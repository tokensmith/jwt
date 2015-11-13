package org.rootservices.jwt.builder;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.TokenType;
import org.rootservices.jwt.signature.signer.Signer;

import java.util.Optional;

/**
 * Created by tommackenzie on 9/15/15.
 */
public class SecureTokenBuilder {
    private Signer signer;

    public SecureTokenBuilder(Signer signer) {
        this.signer = signer;
    }

    public Token build(Algorithm alg, Claims claimNames) {
        Header header = new Header();
        header.setAlgorithm(alg);
        header.setType(Optional.of(TokenType.JWT));

        Token token = new Token();
        token.setHeader(header);
        token.setClaims(claimNames);

        String signature = signer.run(token);
        token.setSignature(Optional.of(signature));

        return token;
    }
}
