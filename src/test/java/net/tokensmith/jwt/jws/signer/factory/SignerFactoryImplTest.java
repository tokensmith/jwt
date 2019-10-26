package net.tokensmith.jwt.jws.signer.factory;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jws.signer.MacSigner;
import net.tokensmith.jwt.jws.signer.RSASigner;
import net.tokensmith.jwt.jws.signer.Signer;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;

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