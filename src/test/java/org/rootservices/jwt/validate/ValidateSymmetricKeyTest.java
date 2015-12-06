package org.rootservices.jwt.validate;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class ValidateSymmetricKeyTest {

    private ValidateKey<SymmetricKey> subject;

    @Before
    public void setUp() {
        subject = new ValidateSymmetricKey();
    }

    @Test
    public void shouldPass() throws InvalidKeyException {
        SymmetricKey key = Factory.makeSymmetricKey();
        Boolean actual = subject.validate(key);

        assertThat(actual, is(true));
    }

    @Test(expected = InvalidKeyException.class)
    public void keyTypeIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKeyType(null);

        subject.validate(key);
    }

    @Test(expected = InvalidKeyException.class)
    public void keyTypeIsNotOctShouldThrowInvalidKeyException() throws InvalidKeyException {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKeyType(KeyType.RSA);

        subject.validate(key);
    }

    @Test(expected = InvalidKeyException.class)
    public void keyIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKey(null);

        subject.validate(key);
    }

    @Test(expected = InvalidKeyException.class)
    public void keyIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKey("");

        subject.validate(key);
    }
}