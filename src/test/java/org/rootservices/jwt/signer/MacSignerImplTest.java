package org.rootservices.jwt.signer;


import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signer.factory.SignerFactory;

import java.io.UnsupportedEncodingException;

import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 8/19/15.
 */
public class MacSignerImplTest {
    private SignerFactory signerFactory;

    @Before
    public void setUp() {
        AppFactory config = new AppFactory();
        signerFactory = config.signerFactory();

    }

    /**
     * Test scenario taken from,
     * https://tools.ietf.org/html/rfc7515#appendix-A.1
     */
    @Test
    public void shouldSignCorrectly() {

        String expected = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        // JSON Web Key
        Key key = new Key();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        // this evaluates to a header and claims that contains \r\n
        byte[] signInput = new byte[] {101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81,
                105, 76, 65, 48, 75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74,
                73, 85, 122, 73, 49, 78, 105, 74, 57, 46, 101, 121, 74, 112, 99, 51,
                77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76, 65, 48, 75, 73, 67,
                74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52, 77, 84,
                107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100,
                72, 65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76,
                109, 78, 118, 98, 83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73,
                106, 112, 48, 99, 110, 86, 108, 102, 81};

        Signer subject = signerFactory.makeSigner(Algorithm.HS256, key);
        String actual = subject.run(signInput);

        assertNotNull(actual);
        assertEquals(actual, expected);
    }
}