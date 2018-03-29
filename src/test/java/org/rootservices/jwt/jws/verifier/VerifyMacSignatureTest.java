package org.rootservices.jwt.jws.verifier;


import helper.entity.Claim;
import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serialization.JWTDeserializer;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;

import static org.junit.Assert.assertTrue;

/**
 * Created by tommackenzie on 8/30/15.
 */
public class VerifyMacSignatureTest {

    private JwtAppFactory appFactory;
    private JWTDeserializer jwtDeserializer;

    @Before
    public void setUp() {
        appFactory = new JwtAppFactory();
        jwtDeserializer = appFactory.jwtDeserializer();
    }

    @Test
    public void verifySecureJwtWithJwtShouldBeTrue() throws InvalidAlgorithmException, InvalidJsonWebKeyException {

        String jwtAsText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        JsonWebToken jwt = null;
        try {
            jwt = jwtDeserializer.stringToJwt(jwtAsText, Claim.class);
        } catch (JsonToJwtException e) {
            e.printStackTrace();
        }

        SymmetricKey key = Factory.makeSymmetricKey();

        VerifySignature subject = appFactory.verifySignature(Algorithm.HS256, key);

        boolean actual = subject.run(jwt);
        assertTrue(actual);
    }

    @Test
    public void verifyUnsecureJwtWithJwtShouldBeTrue() throws InvalidAlgorithmException, InvalidJsonWebKeyException {

        String jwtAsText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        JsonWebToken jwt = null;
        try {
            jwt = jwtDeserializer.stringToJwt(jwtAsText, Claim.class);
        } catch (JsonToJwtException e) {
            e.printStackTrace();
        }

        SymmetricKey key = Factory.makeSymmetricKey();

        VerifySignature subject = appFactory.verifySignature(Algorithm.HS256, key);

        boolean actual = subject.run(jwt);
        assertTrue(actual);
    }

}