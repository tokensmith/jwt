package net.tokensmith.jwt.entity.jwk;

import org.junit.Test;

import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class SymmetricKeyTest {

    @Test
    public void buildShouldBeOk() {
        SymmetricKey actual = new SymmetricKey.Builder()
                .keyId(Optional.of("1234"))
                .key("my-super-secret-key")
                .build();

        assertTrue(actual.getKeyId().isPresent());
        assertThat(actual.getKeyId().get(), is("1234"));
        assertThat(actual.getKeyType(), is(KeyType.OCT));
        assertThat(actual.getKey(), is("my-super-secret-key"));

    }

    @Test
    public void buildMissingKeyIdShouldBeOk() {
        SymmetricKey actual = new SymmetricKey.Builder()
                .key("my-super-secret-key")
                .build();

        assertFalse(actual.getKeyId().isPresent());
        assertThat(actual.getKeyType(), is(KeyType.OCT));
        assertThat(actual.getKey(), is("my-super-secret-key"));

    }

}