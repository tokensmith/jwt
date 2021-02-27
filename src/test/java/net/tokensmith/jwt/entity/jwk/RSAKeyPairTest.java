package net.tokensmith.jwt.entity.jwk;

import org.junit.Test;

import java.math.BigInteger;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class RSAKeyPairTest {

    @Test
    public void buildShouldBeOk() {
        RSAKeyPair actual = new RSAKeyPair.Builder()
                .keyId(Optional.of("1234"))
                .n(BigInteger.valueOf(1))
                .e(BigInteger.valueOf(2))
                .d(BigInteger.valueOf(3))
                .q(BigInteger.valueOf(4))
                .dp(BigInteger.valueOf(5))
                .dq(BigInteger.valueOf(6))
                .qi(BigInteger.valueOf(7))
                .build();

        assertTrue(actual.getKeyId().isPresent());
        assertThat(actual.getKeyId().get(), is("1234"));
        assertThat(actual.getKeyType(), is(KeyType.RSA));
        assertThat(actual.getN(), is(BigInteger.valueOf(1)));
        assertThat(actual.getE(), is(BigInteger.valueOf(2)));
        assertThat(actual.getD(), is(BigInteger.valueOf(3)));
        assertThat(actual.getQ(), is(BigInteger.valueOf(4)));
        assertThat(actual.getDp(), is(BigInteger.valueOf(5)));
        assertThat(actual.getDq(), is(BigInteger.valueOf(6)));
        assertThat(actual.getQi(), is(BigInteger.valueOf(7)));

    }

    @Test
    public void buildMissingKeyIdShouldBeOk() {
        RSAKeyPair actual = new RSAKeyPair.Builder()
                .n(BigInteger.valueOf(1))
                .e(BigInteger.valueOf(2))
                .d(BigInteger.valueOf(3))
                .q(BigInteger.valueOf(4))
                .dp(BigInteger.valueOf(5))
                .dq(BigInteger.valueOf(6))
                .qi(BigInteger.valueOf(7))
                .build();

        assertFalse(actual.getKeyId().isPresent());
        assertThat(actual.getKeyType(), is(KeyType.RSA));
        assertThat(actual.getKeyType(), is(KeyType.RSA));
        assertThat(actual.getN(), is(BigInteger.valueOf(1)));
        assertThat(actual.getE(), is(BigInteger.valueOf(2)));
        assertThat(actual.getD(), is(BigInteger.valueOf(3)));
        assertThat(actual.getQ(), is(BigInteger.valueOf(4)));
        assertThat(actual.getDp(), is(BigInteger.valueOf(5)));
        assertThat(actual.getDq(), is(BigInteger.valueOf(6)));
        assertThat(actual.getQi(), is(BigInteger.valueOf(7)));
    }

}