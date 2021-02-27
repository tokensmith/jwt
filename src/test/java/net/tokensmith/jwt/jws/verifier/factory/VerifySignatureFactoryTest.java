package net.tokensmith.jwt.jws.verifier.factory;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.exception.SignatureException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jws.verifier.VerifyMacSignature;
import net.tokensmith.jwt.jws.verifier.VerifyRsaSignature;
import net.tokensmith.jwt.jws.verifier.VerifySignature;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;


/**
 * Created by tommackenzie on 11/15/15.
 */
public class VerifySignatureFactoryTest {
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

    @Test
    public void testMakeVerifySignatureWhenHS256AndGivenRSAKeyShouldThrowSignatureException() throws Exception {
        VerifySignatureFactory subject = appFactory.verifySignatureFactory();
        RSAPublicKey key = Factory.makeRSAPublicKey();

        SignatureException actual = null;
        try {
            subject.makeVerifySignature(Algorithm.HS256, key);
        } catch (SignatureException e) {
            actual = e;
        }

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getCause(), is(instanceOf(InvalidAlgorithmException.class)));
    }

    @Test
    public void testMakeVerifySignatureWhenHS256AndBadKeyShouldThrowSignatureException() throws Exception {
        VerifySignatureFactory subject = appFactory.verifySignatureFactory();
        SymmetricKey key = Factory.makeBadSymmetricKey();

        SignatureException actual = null;
        try {
            subject.makeVerifySignature(Algorithm.HS256, key);
        } catch (SignatureException e) {
            actual = e;
        }

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getCause(), is(instanceOf(InvalidJsonWebKeyException.class)));
    }

    @Test
    public void testMakeVerifySignatureWhenRsaAndGivenSymmetricKeyShouldThrowSignatureException() throws Exception {
        VerifySignatureFactory subject = appFactory.verifySignatureFactory();
        SymmetricKey key = Factory.makeSymmetricKey();

        SignatureException actual = null;
        try {
            subject.makeVerifySignature(Algorithm.RS256, key);
        } catch (SignatureException e) {
            actual = e;
        }

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getCause(), is(instanceOf(InvalidAlgorithmException.class)));
    }

    @Test
    public void testMakeVerifySignatureWhenRSAAndBadKeyShouldThrowSignatureException() throws Exception {
        VerifySignatureFactory subject = appFactory.verifySignatureFactory();
        RSAPublicKey key = new RSAPublicKey.Builder()
                .n(BigInteger.valueOf(1))
                .e(BigInteger.valueOf(1))
                .build();

        SignatureException actual = null;
        try {
            subject.makeVerifySignature(Algorithm.RS256, key);
        } catch (SignatureException e) {
            actual = e;
        }

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getCause(), is(instanceOf(InvalidJsonWebKeyException.class)));
    }

}