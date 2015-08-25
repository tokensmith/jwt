package org.rootservices.jwt.signer.factory;


import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signer.MacSignerImpl;
import org.rootservices.jwt.signer.Signer;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class SignerFactoryImplTest {
    private SignerFactory subject;

    @Before
    public void setUp() {
        AppFactory appConfig = new AppFactory();
        subject = appConfig.signerFactory();
    }

    @Test
    public void makeSignerShouldCreateMacSigner() {
        Key key = new Key();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        Signer actual = subject.makeSigner(Algorithm.HS256, key);
        assertThat(actual, instanceOf(MacSignerImpl.class));
    }

}