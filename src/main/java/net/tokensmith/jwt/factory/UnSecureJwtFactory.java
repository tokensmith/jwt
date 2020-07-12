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

    public <T extends Claims> JsonWebToken<T> makeJwt(T claimNames) {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        JsonWebToken<T> jwt = new JsonWebToken<T>();
        jwt.setHeader(header);
        jwt.setClaims(claimNames);
        jwt.setSignature(Optional.<byte[]>empty());

        return jwt;
    }
}
