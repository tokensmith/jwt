package net.tokensmith.jwt.jwe.factory;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jwe.Transformation;
import net.tokensmith.jwt.jwk.PrivateKeyTranslator;
import net.tokensmith.jwt.jwk.PublicKeyTranslator;

import javax.crypto.Cipher;

import java.security.interfaces.RSAPrivateCrtKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class CipherRSAFactoryTest {
    private PublicKeyTranslator publicKeyTranslator;
    private PrivateKeyTranslator privateKeyTranslator;
    private CipherRSAFactory subject;

    @Before
    public void setUp() {
        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        publicKeyTranslator = jwtAppFactory.publicKeyFactory();
        privateKeyTranslator = jwtAppFactory.privateKeyFactory();
        subject = new CipherRSAFactory();
    }

    @Test
    public void forEncryptWhenPublicKey() throws Exception {

        RSAPublicKey rsaPublicKey = Factory.makeRSAPublicKey();
        java.security.interfaces.RSAPublicKey jdkPublicKey = publicKeyTranslator.to(rsaPublicKey);

        Cipher actual = subject.forEncrypt(Transformation.RSA_OAEP, jdkPublicKey);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is(Transformation.RSA_OAEP.getValue()));
        assertThat(actual.getIV(), is(nullValue()));
    }

    @Test
    public void forDecryptWhenPrivateKey() throws Exception {
        RSAKeyPair jwk = Factory.makeRSAKeyPair();
        RSAPrivateCrtKey jdkPrivateKey = privateKeyTranslator.to(jwk);

        Cipher actual = subject.forDecrypt(Transformation.RSA_OAEP, jdkPrivateKey);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getAlgorithm(), is(Transformation.RSA_OAEP.getValue()));
        assertThat(actual.getIV(), is(nullValue()));
    }
}