package org.rootservices.jwt.signature;


import helper.entity.Claim;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.serializer.JWTSerializer;

import static org.junit.Assert.assertTrue;

/**
 * Created by tommackenzie on 8/30/15.
 */
public class VerifySignatureImplTest {

    private VerifySignature subject;
    private JWTSerializer jwtSerializer;

    @Before
    public void setUp() {
        AppFactory appFactory = new AppFactory();
        subject = appFactory.verifySignature();
        jwtSerializer = appFactory.jwtSerializer();
    }

    @Test
    public void verifySecureTokenWithJwtShouldBeTrue() {

        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        Token token = jwtSerializer.jwtToToken(jwt, Claim.class);

        SymmetricKey key = new SymmetricKey();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        boolean actual = subject.run(token, key);
        assertTrue(actual);
    }

    @Test
    public void verifyUnsecureTokenWithJwtShouldBeTrue() {

        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        Token token = jwtSerializer.jwtToToken(jwt, Claim.class);

        SymmetricKey key = new SymmetricKey();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        boolean actual = subject.run(token, key);
        assertTrue(actual);
    }

}