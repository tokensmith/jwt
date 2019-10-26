package net.tokensmith.jwt.jws.verifier.factory;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jws.verifier.VerifyMacSignature;
import net.tokensmith.jwt.jws.verifier.VerifyRsaSignature;
import net.tokensmith.jwt.jws.verifier.VerifySignature;

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