package org.rootservices.jwt.builder;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.TokenType;
import org.rootservices.jwt.signature.signer.InvalidJsonWebToken;
import org.rootservices.jwt.signature.signer.Signer;

import java.util.Optional;

/**
 * Created by tommackenzie on 9/15/15.
 */
public class SecureJwtBuilder {
    private Signer signer;

    public SecureJwtBuilder(Signer signer) {
        this.signer = signer;
    }

    public JsonWebToken build(Algorithm alg, Claims claimNames) throws InvalidJsonWebToken {
        return build(alg, claimNames, Optional.<String>empty());
    }

    public JsonWebToken build(Algorithm alg, Claims claimNames, Optional<String> keyId) throws InvalidJsonWebToken {
        Header header = new Header();
        header.setAlgorithm(alg);
        header.setType(Optional.of(TokenType.JWT));
        header.setKeyId(keyId);

        JsonWebToken jwt = new JsonWebToken();
        jwt.setHeader(header);
        jwt.setClaims(claimNames);

        String signature = signer.run(jwt);
        jwt.setSignature(Optional.of(signature));

        return jwt;
    }

}
