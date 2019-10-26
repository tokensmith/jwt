package net.tokensmith.jwt.serialization;


import helper.entity.Claim;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.Header;
import net.tokensmith.jwt.serialization.exception.JsonException;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;


public class SerdesTest {

    private JwtAppFactory appFactory;

    @Before
    public void setUp() {
        appFactory = new JwtAppFactory();
    }

    @Test
    public void headerToJson() throws JsonException {
        Serdes subject = appFactory.serdes();
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);

        byte[] actual = subject.objectToByte(header);
        String actualAsString = new String(actual, StandardCharsets.UTF_8);
        assertThat(actualAsString, is("{\"alg\":\"none\"}"));
    }

    @Test
    public void claimToJsonExpectExcludesNullAndOptionalEmpty() throws JsonException {
        Serdes subject = appFactory.serdes();
        Claim claim = new Claim();

        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);

        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        byte[] actual = subject.objectToByte(claim);
        String actualAsString = new String(actual, StandardCharsets.UTF_8);
        assertThat(actualAsString, is("{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"));
    }

    @Test
    public void jsonToUnsecuredHeader() throws JsonException {
        Serdes subject = appFactory.serdes();
        byte[] json = "{\"alg\":\"none\"}".getBytes();
        Header actual = (Header) subject.jsonBytesToObject(json, Header.class);
        assertThat(actual.getAlgorithm(), is(Algorithm.NONE));
    }

    @Test
    public void jsonToClaim() throws JsonException {
        Serdes subject = appFactory.serdes();
        byte[] json = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}".getBytes();
        Claim actual = (Claim) subject.jsonBytesToObject(json, Claim.class);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.isUriIsRoot(), is(true));
        assertThat(actual.getIssuer().isPresent(), is(true));
        assertThat(actual.getIssuer().get(), is("joe"));
        assertThat(actual.getExpirationTime().isPresent(), is(true));
        assertThat(actual.getExpirationTime().get(), is(1300819380L));
        assertThat(actual.getSubject().isPresent(), is(false));
        assertThat(actual.getAudience(), is(nullValue()));
        assertThat(actual.getNotBefore().isPresent(), is(false));
        assertThat(actual.getIssuedAt().isPresent(), is(false));
        assertThat(actual.getJwtId().isPresent(), is(false));
    }

    @Test(expected=JsonException.class)
    public void jsonBytesToObjectShouldThrowJsonException() throws JsonException {
        Serdes subject = appFactory.serdes();
        byte[] invalidJson = "{\"iss\":\"joe\"".getBytes();

        subject.jsonBytesToObject(invalidJson, Claim.class);
    }
}