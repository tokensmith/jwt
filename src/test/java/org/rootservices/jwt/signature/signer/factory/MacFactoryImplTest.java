package org.rootservices.jwt.signature.signer.factory;


import helper.entity.Factory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.hmac.MacFactory;
import org.rootservices.jwt.signature.signer.factory.hmac.exception.MacException;

import javax.crypto.Mac;
import java.util.Base64;

import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class MacFactoryImplTest {
    private MacFactory subject;

    @Before
    public void setUp() {
        AppFactory appFactory = new AppFactory();
        subject = appFactory.macFactory();
    }

    @Test
    public void makeKeyShouldBeHS256WithSecretKey() {
        SymmetricKey key = Factory.makeSymmetricKey();

        java.security.Key actual = subject.makeKey(Algorithm.HS256, key);
        assertNotNull(actual);
        Assert.assertEquals(actual.getAlgorithm(), SignAlgorithm.HS256.getValue());

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        assertEquals(encoder.encodeToString(actual.getEncoded()), key.getKey());
    }

    @Test
    public void makeMacShouldBeHS256Alg() throws MacException {
        SymmetricKey key = Factory.makeSymmetricKey();

        Mac actual = subject.makeMac(Algorithm.HS256, key);
        assertNotNull(actual);
        Assert.assertEquals(actual.getAlgorithm(), SignAlgorithm.HS256.getValue());
    }
}