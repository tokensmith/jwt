package org.rootservices.jwt.signature.verifier;

import helper.entity.Claim;
import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.signature.verifier.VerifySignature;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class VerifyRsaSignatureTest {
    private AppFactory appFactory;

    @Before
    public void setUp() {
        this.appFactory = new AppFactory();
    }

    @Test
    public void testRunShouldBeTrue() throws Exception {
        String jwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        JWTSerializer serializer = appFactory.jwtSerializer();
        Token token = serializer.jwtToToken(jwt, Claim.class);

        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        VerifySignature subject = appFactory.verifyRsaSignature(Algorithm.RS256, publicKey);

        // verify the signature
        boolean isVerified = subject.run(token, publicKey);

        assertThat(isVerified, is(true));

    }
}