package net.tokensmith.jwt.jws.verifier;

import helper.entity.Claim;
import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.serialization.JwtSerde;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class VerifyRsaSignatureTest {
    private JwtAppFactory appFactory;

    @Before
    public void setUp() {
        this.appFactory = new JwtAppFactory();
    }

    @Test
    public void testRunShouldBeTrue() throws Exception {
        String jwtAsText = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        JwtSerde serializer = appFactory.jwtSerde();
        JsonWebToken<Claim> jwt = serializer.stringToJwt(jwtAsText, Claim.class);

        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        VerifySignature subject = appFactory.verifySignature(Algorithm.RS256, publicKey);

        // verify the signature
        boolean isVerified = subject.run(jwt);

        assertThat(isVerified, is(true));

    }
}