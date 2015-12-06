package org.rootservices.jwt.signature.signer.factory;


import helper.entity.Factory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.hmac.MacFactory;
import org.rootservices.jwt.signature.signer.factory.hmac.MacFactoryImpl;

import java.util.Base64;
import java.util.Optional;

import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class MacFactoryImplTest {
    private MacFactory macFactory;

    @Before
    public void setUp() {
        macFactory = new MacFactoryImpl();
    }

    @Test
    public void makeKeyShouldBeHS256WithSecretKey() {
        SymmetricKey key = Factory.makeSymmetricKey();

        java.security.Key actual = macFactory.makeKey(Algorithm.HS256, key);
        assertNotNull(actual);
        Assert.assertEquals(actual.getAlgorithm(), SignAlgorithm.HS256.getValue());

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        assertEquals(encoder.encodeToString(actual.getEncoded()), key.getKey());
    }

}