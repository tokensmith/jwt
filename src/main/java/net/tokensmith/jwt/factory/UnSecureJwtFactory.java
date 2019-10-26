package net.tokensmith.jwt.factory;

import net.tokensmith.jwt.entity.jwt.Claims;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.Header;


import java.util.Optional;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class UnSecureJwtFactory {

    public JsonWebToken makeJwt(Claims claimNames) {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        JsonWebToken jwt = new JsonWebToken();
        jwt.setHeader(header);
        jwt.setClaims(claimNames);
        jwt.setSignature(Optional.<byte[]>empty());

        return jwt;
    }
}
