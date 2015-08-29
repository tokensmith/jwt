package org.rootservices.jwt.signature.signer.factory;


import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;

import java.util.Base64;

import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class KeyFactoryImplTest {
    private KeyFactory keyFactory;

    @Before
    public void setUp() {
        keyFactory = new KeyFactoryImpl();
    }

    @Test
    public void makeKeyShouldBeHS256WithSecretKey() {
        Key key = new Key();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        java.security.Key actual = keyFactory.makeKey(Algorithm.HS256, key);
        assertNotNull(actual);
        Assert.assertEquals(actual.getAlgorithm(), SignAlgorithm.HS256.getValue());

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        assertEquals(encoder.encodeToString(actual.getEncoded()), key.getKey());
    }

}