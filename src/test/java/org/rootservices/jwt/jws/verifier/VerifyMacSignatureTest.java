package org.rootservices.jwt.jws.verifier;


import helper.entity.Claim;
import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serialization.JwtSerde;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import static org.junit.Assert.assertTrue;


public class VerifyMacSignatureTest {

    private JwtAppFactory appFactory;
    private JwtSerde jwtSerde;

    @Before
    public void setUp() {
        appFactory = new JwtAppFactory();
        jwtSerde = appFactory.jwtSerde();
    }

    @Test
    public void verifySecureJwtWithJwtShouldBeTrue() throws Exception {

        String jwtAsText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        JsonWebToken jwt = null;
        try {
            jwt = jwtSerde.stringToJwt(jwtAsText, Claim.class);
        } catch (JsonToJwtException e) {
            e.printStackTrace();
        }

        SymmetricKey key = Factory.makeSymmetricKey();

        VerifySignature subject = appFactory.verifySignature(Algorithm.HS256, key);

        boolean actual = subject.run(jwt);
        assertTrue(actual);
    }

    @Test
    public void verifyUnsecureJwtWithJwtShouldBeTrue() throws Exception {

        String jwtAsText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        JsonWebToken jwt = null;
        try {
            jwt = jwtSerde.stringToJwt(jwtAsText, Claim.class);
        } catch (JsonToJwtException e) {
            e.printStackTrace();
        }

        SymmetricKey key = Factory.makeSymmetricKey();

        VerifySignature subject = appFactory.verifySignature(Algorithm.HS256, key);

        boolean actual = subject.run(jwt);
        assertTrue(actual);
    }

}