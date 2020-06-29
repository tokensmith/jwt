package net.tokensmith.jwt.jws.signer.factory;


import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jws.signer.SignAlgorithm;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.hmac.MacFactory;
import net.tokensmith.jwt.jws.signer.factory.hmac.exception.SecurityKeyException;

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
    public void makeKeyShouldBeHS256WithSecretKey() throws Exception {
        SymmetricKey key = Factory.makeSymmetricKey();

        java.security.Key actual = subject.makeKey(SignAlgorithm.HS256, key);
        assertNotNull(actual);
        assertEquals(actual.getAlgorithm(), SignAlgorithm.HS256.getJdkAlgorithm());

        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        assertEquals(encoder.encodeToString(actual.getEncoded()), key.getKey());
    }

    @Test
    public void makeMacShouldBeHS256Alg() throws Exception {
        SymmetricKey key = Factory.makeSymmetricKey();

        Mac actual = subject.makeMac(SignAlgorithm.HS256, key);
        assertNotNull(actual);
        assertEquals(actual.getAlgorithm(), SignAlgorithm.HS256.getJdkAlgorithm());
    }
}