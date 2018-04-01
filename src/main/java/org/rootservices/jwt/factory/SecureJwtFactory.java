package org.rootservices.jwt.factory;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.TokenType;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;
import org.rootservices.jwt.jws.signer.Signer;

import java.util.Optional;


public class SecureJwtFactory {
    private Signer signer;
    private Algorithm algorithm;
    private Optional<String> keyId;

    public SecureJwtFactory(Signer signer, Algorithm algorithm, Optional<String> keyId) {
        this.signer = signer;
        this.algorithm = algorithm;
        this.keyId = keyId;
    }

    public JsonWebToken makeJwt(Claims claimNames) throws JwtToJsonException {
        Header header = new Header();
        header.setAlgorithm(algorithm);
        header.setType(Optional.of(TokenType.JWT));
        header.setKeyId(keyId);

        JsonWebToken jwt = new JsonWebToken();
        jwt.setHeader(header);
        jwt.setClaims(claimNames);

        byte[] signature = signer.run(jwt);
        jwt.setSignature(Optional.of(signature));

        return jwt;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public Optional<String> getKeyId() {
        return keyId;
    }
}
