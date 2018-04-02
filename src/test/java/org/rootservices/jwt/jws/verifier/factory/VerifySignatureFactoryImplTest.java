package org.rootservices.jwt.jws.verifier.factory;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.jws.verifier.VerifyMacSignature;
import org.rootservices.jwt.jws.verifier.VerifyRsaSignature;
import org.rootservices.jwt.jws.verifier.VerifySignature;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 11/15/15.
 */
public class VerifySignatureFactoryImplTest {
    private JwtAppFactory appFactory;

    @Before
    public void setUp() {
        this.appFactory = new JwtAppFactory();
    }

    @Test
    public void testMakeVerifySignatureShouldBeVerifyMacSignature() throws Exception {
        VerifySignatureFactory subject = appFactory.verifySignatureFactory();
        SymmetricKey key = Factory.makeSymmetricKey();

        VerifySignature verifySignature = subject.makeVerifySignature(Algorithm.HS256, key);

        assertThat(verifySignature, instanceOf(VerifyMacSignature.class));
    }

    @Test
    public void testMakeVerifySignatureShouldBeVerifyRSASignature() throws Exception {
        VerifySignatureFactory subject = appFactory.verifySignatureFactory();
        RSAPublicKey key = Factory.makeRSAPublicKey();

        VerifySignature verifySignature = subject.makeVerifySignature(Algorithm.RS256, key);

        assertThat(verifySignature, instanceOf(VerifyRsaSignature.class));
    }
}