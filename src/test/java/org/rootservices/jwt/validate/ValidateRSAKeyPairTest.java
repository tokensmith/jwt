package org.rootservices.jwt.validate;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class ValidateRSAKeyPairTest {
    private ValidateKey<RSAKeyPair> subject;

    @Before
    public void setUp() {
        subject = new ValidateRSAKeyPair();
    }

    @Test
    public void shouldPass() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();

        Boolean actual = subject.validate(keyPair);
        assertThat(actual, is(true));
    }

    @Test(expected = InvalidKeyException.class)
    public void keyTypeIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setKeyType(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void keyTypeIsNotRSAShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setKeyType(KeyType.OCT);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void DIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setD(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void DIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setD("");

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void DpIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setDp(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void DpIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setDp("");

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void DqIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setDq(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void DqIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setDq("");

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void EIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setE(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void EIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setE("");

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void NIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setN(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void NIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setN("");

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void PIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setP(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void PIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setP("");

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void QIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setQ(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void QIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setQ("");

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void QiIsNullShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setQi(null);

        subject.validate(keyPair);
    }

    @Test(expected = InvalidKeyException.class)
    public void QiIsEmptyShouldThrowInvalidKeyException() throws InvalidKeyException {
        RSAKeyPair keyPair = Factory.makeRSAKeyPair();
        keyPair.setQi("");

        subject.validate(keyPair);
    }
}