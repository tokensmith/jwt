package org.rootservices.jwt.signature.signer.factory;


import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.hmac.MacFactory;
import org.rootservices.jwt.signature.signer.factory.hmac.exception.SecurityKeyException;

import javax.crypto.Mac;
import java.util.Base64;

import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class MacFactoryTest {
    private MacFactory subject;

    @Before
    public void setUp() {
        JwtAppFactory appFactory = new JwtAppFactory();
        subject = appFactory.macFactory();
    }

    @Test
    public void makeKeyShouldBeHS256WithSecretKey() {
        SymmetricKey key = Factory.makeSymmetricKey();

        java.security.Key actual = subject.makeKey(SignAlgorithm.HS256, key);
        assertNotNull(actual);
        assertEquals(actual.getAlgorithm(), SignAlgorithm.HS256.getJdkAlgorithm());

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        assertEquals(encoder.encodeToString(actual.getEncoded()), key.getKey());
    }

    @Test
    public void makeMacShouldBeHS256Alg() throws InvalidAlgorithmException, SecurityKeyException {
        SymmetricKey key = Factory.makeSymmetricKey();

        Mac actual = subject.makeMac(SignAlgorithm.HS256, key);
        assertNotNull(actual);
        assertEquals(actual.getAlgorithm(), SignAlgorithm.HS256.getJdkAlgorithm());
    }
}