package org.rootservices.jwt.jwe.factory;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.jwk.PrivateKeyFactory;
import org.rootservices.jwt.jwk.PublicKeyFactory;

import javax.crypto.Cipher;

import java.security.interfaces.RSAPrivateCrtKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.*;

public class CipherRSAFactoryTest {
    private PublicKeyFactory publicKeyFactory;
    private PrivateKeyFactory privateKeyFactory;
    private CipherRSAFactory subject;

    @Before
    public void setUp() {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        publicKeyFactory = jwtAppFactory.publicKeyFactory();
        privateKeyFactory = jwtAppFactory.privateKeyFactory();
        subject = new CipherRSAFactory();
    }

    @Test
    public void forEncryptWhenPublicKey() throws Exception {

        RSAPublicKey rsaPublicKey = Factory.makeRSAPublicKey();
        java.security.interfaces.RSAPublicKey jdkPublicKey = publicKeyFactory.makePublicKey(rsaPublicKey);

        Cipher actual = subject.forEncrypt(Transformation.RSA_OAEP, jdkPublicKey);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is(Transformation.RSA_OAEP.getValue()));
        assertThat(actual.getIV(), is(nullValue()));
    }

    @Test
    public void forDecryptWhenPrivateKey() throws Exception {
        RSAKeyPair jwk = Factory.makeRSAKeyPair();
        RSAPrivateCrtKey jdkPrivateKey = privateKeyFactory.makePrivateKey(jwk);

        Cipher actual = subject.forDecrypt(Transformation.RSA_OAEP, jdkPrivateKey);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is(Transformation.RSA_OAEP.getValue()));
        assertThat(actual.getIV(), is(nullValue()));
    }
}