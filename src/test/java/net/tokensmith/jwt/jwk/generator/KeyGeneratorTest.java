package net.tokensmith.jwt.jwk.generator;

import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwk.Use;
import org.junit.Test;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class KeyGeneratorTest {
    private static final JwtAppFactory jwtAppFactory = new JwtAppFactory();

    @Test
    public void symmetricKeyShouldBeOk() throws Exception {
        KeyGenerator subject = jwtAppFactory.keyGenerator();

        SymmetricKey actual = subject.symmetricKey(Optional.of("123"), Use.SIGNATURE);

        assertTrue(actual.getKeyId().isPresent());
        assertThat(actual.getKeyId().get(), is("123"));
        assertThat(actual.getUse(), is(Use.SIGNATURE));
        assertThat(actual.getKey(), is(notNullValue()));

        // key should be able to be base64 decoded.
        try {
            jwtAppFactory.urlDecoder().decode(actual.getKey());
        } catch (IllegalArgumentException e) {
            fail("key is not base 64 encoded. " + e.getMessage());
        }

    }

    @Test
    public void rsaKeyPair1024ShouldBeOk() throws Exception {
        KeyGenerator subject = jwtAppFactory.keyGenerator();

        RSAKeyPair actual = subject.rsaKeyPair(KeyGenerator.RSA_1024, Optional.of("123"), Use.SIGNATURE);

        assertTrue(actual.getKeyId().isPresent());
        assertThat(actual.getKeyId().get(), is("123"));
        assertThat(actual.getUse(), is(Use.SIGNATURE));
        assertThat(actual.getN(), is(notNullValue()));
        assertThat(actual.getE(), is(notNullValue()));
        assertThat(actual.getD(), is(notNullValue()));
        assertThat(actual.getP(), is(notNullValue()));
        assertThat(actual.getQ(), is(notNullValue()));
        assertThat(actual.getDp(), is(notNullValue()));
        assertThat(actual.getDq(), is(notNullValue()));
        assertThat(actual.getQi(), is(notNullValue()));
    }

    @Test
    public void rsaKeyPair2048ShouldBeOk() throws Exception {
        KeyGenerator subject = jwtAppFactory.keyGenerator();

        RSAKeyPair actual = subject.rsaKeyPair(KeyGenerator.RSA_2048, Optional.of("123"), Use.SIGNATURE);

        assertTrue(actual.getKeyId().isPresent());
        assertThat(actual.getKeyId().get(), is("123"));
        assertThat(actual.getUse(), is(Use.SIGNATURE));
        assertThat(actual.getN(), is(notNullValue()));
        assertThat(actual.getE(), is(notNullValue()));
        assertThat(actual.getD(), is(notNullValue()));
        assertThat(actual.getP(), is(notNullValue()));
        assertThat(actual.getQ(), is(notNullValue()));
        assertThat(actual.getDp(), is(notNullValue()));
        assertThat(actual.getDq(), is(notNullValue()));
        assertThat(actual.getQi(), is(notNullValue()));
    }

    @Test
    public void rsaKeyPair4096ShouldBeOk() throws Exception {
        KeyGenerator subject = jwtAppFactory.keyGenerator();

        RSAKeyPair actual = subject.rsaKeyPair(KeyGenerator.RSA_4096, Optional.of("123"), Use.SIGNATURE);

        assertTrue(actual.getKeyId().isPresent());
        assertThat(actual.getKeyId().get(), is("123"));
        assertThat(actual.getUse(), is(Use.SIGNATURE));
        assertThat(actual.getN(), is(notNullValue()));
        assertThat(actual.getE(), is(notNullValue()));
        assertThat(actual.getD(), is(notNullValue()));
        assertThat(actual.getP(), is(notNullValue()));
        assertThat(actual.getQ(), is(notNullValue()));
        assertThat(actual.getDp(), is(notNullValue()));
        assertThat(actual.getDq(), is(notNullValue()));
        assertThat(actual.getQi(), is(notNullValue()));
    }

    @Test
    public void rsa1024IsOk() throws Exception {
        assertThat(KeyGenerator.RSA_1024, is(1024));
    }

    @Test
    public void rsa2048IsOk() throws Exception {
        assertThat(KeyGenerator.RSA_2048, is(2048));
    }

    @Test
    public void rsa4096IsOk() throws Exception {
        assertThat(KeyGenerator.RSA_4096, is(4096));
    }
}