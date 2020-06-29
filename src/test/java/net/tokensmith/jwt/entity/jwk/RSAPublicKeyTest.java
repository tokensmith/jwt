package net.tokensmith.jwt.entity.jwk;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Optional;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class RSAPublicKeyTest {

    @Test
    public void buildShouldBeOk() {
        RSAPublicKey actual = new RSAPublicKey.Builder()
                .keyId(Optional.of("1234"))
                .n(BigInteger.valueOf(5678))
                .e(BigInteger.valueOf(91011))
                .build();

        assertTrue(actual.getKeyId().isPresent());
        assertThat(actual.getKeyId().get(), is("1234"));
        assertThat(actual.getKeyType(), is(KeyType.RSA));
        assertThat(actual.getN(), is(BigInteger.valueOf(5678)));
        assertThat(actual.getE(), is(BigInteger.valueOf(91011)));
    }

    @Test
    public void buildMissingKeyIdShouldBeOk() {
        RSAPublicKey actual = new RSAPublicKey.Builder()
                .n(BigInteger.valueOf(5678))
                .e(BigInteger.valueOf(91011))
                .build();

        assertFalse(actual.getKeyId().isPresent());
        assertThat(actual.getKeyType(), is(KeyType.RSA));
        assertThat(actual.getN(), is(BigInteger.valueOf(5678)));
        assertThat(actual.getE(), is(BigInteger.valueOf(91011)));
    }
}