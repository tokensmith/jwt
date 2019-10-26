package net.tokensmith.jwt.jws.verifier;


import helper.entity.Claim;
import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.serialization.JwtSerde;
import net.tokensmith.jwt.serialization.exception.JsonToJwtException;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;

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