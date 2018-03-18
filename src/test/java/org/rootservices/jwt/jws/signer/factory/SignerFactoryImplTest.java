package org.rootservices.jwt.jws.signer.factory;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.jws.signer.MacSigner;
import org.rootservices.jwt.jws.signer.RSASigner;
import org.rootservices.jwt.jws.signer.Signer;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;

import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 8/31/15.
 */
public class SignerFactoryImplTest {
    SignerFactory subject;

    @Before
    public void setUp() throws Exception {
        JwtAppFactory appFactory = new JwtAppFactory();
        subject = appFactory.signerFactory();
    }

    @Test
    public void shouldCreateMacSigner() throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        SymmetricKey key = Factory.makeSymmetricKey();

        Signer actual = subject.makeSigner(Algorithm.HS256, key);
        assertThat(actual, instanceOf(MacSigner.class));
    }

    @Test
    public void shouldCreateRSASigner() throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        RSAKeyPair key = Factory.makeRSAKeyPair();
        Signer actual = subject.makeSigner(Algorithm.RS256, key);

        assertThat(actual, instanceOf(RSASigner.class));
    }
}