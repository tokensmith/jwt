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
    public void shouldCreateMacSigner() {
        SymmetricKey key = new SymmetricKey(
                Optional.<String>empty(),
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        );

        Signer actual = subject.makeSigner(Algorithm.HS256, key);
        assertThat(actual, instanceOf(MacSigner.class));
    }

    @Test
    public void shouldCreateRSASigner() {
        RSAKeyPair key = Factory.makeRSAKeyPair();
        Signer actual = subject.makeSigner(Algorithm.RS256, key);

        assertThat(actual, instanceOf(RSASigner.class));
    }
}