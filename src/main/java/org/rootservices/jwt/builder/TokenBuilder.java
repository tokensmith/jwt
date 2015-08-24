package org.rootservices.jwt.builder;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.RegisteredClaimNames;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.TokenType;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.signer.Signer;
import org.rootservices.jwt.signer.factory.SignerFactory;

import java.util.Optional;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class TokenBuilder {
    private JWTSerializer jwtSerializer;
    private SignerFactory signerFactory;


    public TokenBuilder(JWTSerializer jwtSerializer, SignerFactory signerFactory) {
        this.jwtSerializer = jwtSerializer;
        this.signerFactory = signerFactory;
    }
    
    public Token makeUnsecuredToken(RegisteredClaimNames claimNames) {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        Token token = new Token();
        token.setHeader(header);
        token.setClaimNames(claimNames);
        token.setSignature(Optional.<String>empty());

        return token;
    };

    public Token makeSignedToken(Algorithm alg, Key jwk, RegisteredClaimNames claimNames) {
        Header header = new Header();
        header.setAlgorithm(alg);
        header.setType(TokenType.JWT);

        Token token = new Token();
        token.setHeader(header);
        token.setClaimNames(claimNames);

        String jwt = jwtSerializer.tokenToJwt(token);
        // remove trailing "." from the jwt.
        String signInput = jwt.substring(0, jwt.length()-1);

        Signer signer = signerFactory.makeSigner(alg, jwk);

        String signature = signer.run(signInput.getBytes());
        token.setSignature(Optional.of(signature));

        return token;
    }
}
