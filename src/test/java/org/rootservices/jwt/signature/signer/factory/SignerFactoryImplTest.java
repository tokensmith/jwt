package org.rootservices.jwt.signature.signer.factory;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.MacSigner;
import org.rootservices.jwt.signature.signer.RSASigner;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebTokenException;
import org.rootservices.jwt.signature.signer.factory.exception.SignerException;

import java.util.Optional;

import static org.hamcrest.core.IsInstanceOf.instanceOf;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 8/31/15.
 */
public class SignerFactoryImplTest {
    SignerFactory subject;

    @Before
    public void setUp() throws Exception {
        AppFactory appFactory = new AppFactory();
        subject = appFactory.signerFactory();
    }

    @Test
    public void shouldCreateMacSigner() throws InvalidAlgorithmException, InvalidJsonWebTokenException {
        SymmetricKey key = Factory.makeSymmetricKey();

        Signer actual = subject.makeSigner(Algorithm.HS256, key);
        assertThat(actual, instanceOf(MacSigner.class));
    }

    @Test
    public void shouldCreateRSASigner() throws InvalidAlgorithmException, InvalidJsonWebTokenException {
        RSAKeyPair key = Factory.makeRSAKeyPair();
        Signer actual = subject.makeSigner(Algorithm.RS256, key);

        assertThat(actual, instanceOf(RSASigner.class));
    }
}