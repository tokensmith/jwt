package org.rootservices.jwt.validate;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class ValidateRSAPublicKeyTest {
    private ValidateKey<RSAPublicKey> subject;

    @Before
    public void setUp() {
        subject = new ValidateRSAPublicKey();
    }

    @Test
    public void shouldPass() throws InvalidKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();

        Boolean actual = subject.validate(publicKey);
        assertThat(actual, is(true));
    }

    @Test(expected = InvalidKeyException.class)
    public void keyTypeIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        publicKey.setKeyType(null);

        subject.validate(publicKey);
    }

    @Test(expected = InvalidKeyException.class)
    public void keyTypeIsNotRSAShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        publicKey.setKeyType(KeyType.OCT);

        subject.validate(publicKey);
    }

    @Test(expected = InvalidKeyException.class)
    public void NIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        publicKey.setN(null);

        subject.validate(publicKey);
    }

    @Test(expected = InvalidKeyException.class)
    public void NIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        publicKey.setN("");

        subject.validate(publicKey);
    }

    @Test(expected = InvalidKeyException.class)
    public void EIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        publicKey.setE(null);

        subject.validate(publicKey);
    }

    @Test(expected = InvalidKeyException.class)
    public void EIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        publicKey.setE("");

        subject.validate(publicKey);
    }
}