package org.rootservices.jwt.signature.signer;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebKeyException;


import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 11/12/15.
 */
public class RSASignerTest {
    private AppFactory appFactory;

    @Before
    public void setUp() {
        this.appFactory = new AppFactory();
    }

    /**
     * This test scenario is taken from,
     * https://tools.ietf.org/html/rfc7515#appendix-A.2
     *
     * @throws Exception
     */
    @Test
    public void signBytesWithRS256ShouldSignCorrectly() throws Exception {
        String expected = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

        RSAKeyPair jwk = Factory.makeRSAKeyPair();
        Signer subject =  appFactory.signerFactory().makeSigner(Algorithm.RS256, jwk);

        byte[] signInput = new byte[] {
                101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73,
                49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105,
                74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67, 74, 108, 101, 72,
                65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84, 107, 122, 79, 68,
                65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65, 54, 76,
                121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118,
                98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48,
                99, 110, 86, 108, 102, 81};

        String actual = subject.run(signInput);

        assertThat(actual, is(notNullValue()));
        assertThat(actual, is(expected));
    }

    /**
     * This scenario is taken from,
     * https://tools.ietf.org/html/rfc7515#appendix-A.2
     *
     * The signature is different b/c there are no line breaks in the
     * signing input value.
     *
     * @throws Exception
     */
    @Test
    public void signTokenWithRS256ShouldSignCorrectly() throws InvalidAlgorithmException, InvalidJsonWebKeyException, JwtToJsonException {
        String expected = "el3lmx2zFYSGmoOC5sJFjV4nCFyb6_2nY5WDSv_d9L2cw857vQBhjV2xybTQz5_4IIVLxpollxyomEQpC1xwZSZoU9lrmNau2TGg1iFGjyIXrtZy-UxV0t_xSwujFlA_WNFjw6eLI00ji3EcuOiMpqPa8IOTfXijtgkCx7oVweb2IVO6ZjMcssvhA7s3ezF8YHf6ewHK74UF4o0RuKn4K1PjBbmxDu3TXMOp69IvbnCj2ku--9QI7H9DFjiNVyWWnpz3wekGZuUePAj5GkrbPgvwhVVUiTcczYy55MUaF7mPjkb7JGEk2sH4lCa1Jlvz9xgYMdYTfbwmT9Wgvq_Usg";

        RSAKeyPair jwk = Factory.makeRSAKeyPair();
        Signer subject =  appFactory.signerFactory().makeSigner(Algorithm.RS256, jwk);

        JsonWebToken jwt = Factory.makeToken(Algorithm.RS256, Optional.empty());

        String actual = subject.run(jwt);

        assertThat(actual, is(notNullValue()));
        assertThat(actual, is(expected));
    }
}