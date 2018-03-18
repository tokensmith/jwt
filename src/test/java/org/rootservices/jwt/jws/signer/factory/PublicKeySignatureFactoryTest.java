package org.rootservices.jwt.jws.signer.factory;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.jws.signer.SignAlgorithm;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.jws.signer.factory.rsa.PublicKeySignatureFactory;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.RSAPublicKeyException;

import java.math.BigInteger;
import java.security.Signature;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class PublicKeySignatureFactoryTest {
    private JwtAppFactory appFactory;
    private PublicKeySignatureFactory subject;

    @Before
    public void setUp() {
        this.appFactory = new JwtAppFactory();
        this.subject = appFactory.publicKeySignatureFactory();
    }

    @Test
    public void makePublicKeyShouldBeRsaPublicKey() throws PublicKeyException {

        RSAPublicKey publicKey = Factory.makeRSAPublicKey();

        // expected values
        BigInteger modulus = new BigInteger("20446702916744654562596343388758805860065209639960173505037453331270270518732245089773723012043203236097095623402044690115755377345254696448759605707788965848889501746836211206270643833663949992536246985362693736387185145424787922241585721992924045675229348655595626434390043002821512765630397723028023792577935108185822753692574221566930937805031155820097146819964920270008811327036286786392793593121762425048860211859763441770446703722015857250621107855398693133264081150697423188751482418465308470313958250757758547155699749157985955379381294962058862159085915015369381046959790476428631998204940879604226680285601");
        BigInteger publicExponent = new BigInteger("65537");

        java.security.interfaces.RSAPublicKey actual = subject.makePublicKey(publicKey);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is("RSA"));
        assertThat(actual.getModulus(), is(modulus));
        assertThat(actual.getPublicExponent(), is(publicExponent));

    }

    @Test(expected = PublicKeyException.class)
    public void makePublicKeyWhenKeyIsNot512ShouldThrowPublicKeyException() throws PublicKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        publicKey.setN(new BigInteger("1"));

        subject.makePublicKey(publicKey);
    }

        @Test
    public void testMakeSignatureShouldBeRS256() throws InvalidAlgorithmException, PublicKeyException, RSAPublicKeyException {
        RSAPublicKey publicKey = Factory.makeRSAPublicKey();
        Signature signature = subject.makeSignature(SignAlgorithm.RS256, publicKey);

        assertThat(signature.getAlgorithm(), is(SignAlgorithm.RS256.getJdkAlgorithm()));
    }
}