package org.rootservices.jwt.serializer;


import helper.entity.Claim;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.exception.JsonException;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 * Created by tommackenzie on 8/12/15.
 */
public class SerializerImplTest {

    private AppFactory appFactory;

    @Before
    public void setUp() {
        appFactory = new AppFactory();
    }

    @Test
    public void headerToJson() throws JsonException {
        Serializer subject = appFactory.serializer();
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);
        String json = subject.objectToJson(header);
        assertThat(json, is("{\"alg\":\"none\"}"));
    }

    @Test
    public void claimToJsonExpectExcludesNullAndOptionalEmpty() throws JsonException {
        Serializer subject = appFactory.serializer();
        Claim claim = new Claim();

        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);

        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        String json = subject.objectToJson(claim);
        assertThat(json, is("{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"));
    }

    @Test
    public void jsonToUnsecuredHeader() throws JsonException {
        Serializer subject = appFactory.serializer();
        byte[] json = "{\"alg\":\"none\"}".getBytes();
        Header actual = (Header) subject.jsonBytesToObject(json, Header.class);
        assertThat(actual.getAlgorithm(), is(Algorithm.NONE));
    }

    @Test
    public void jsonToClaim() throws JsonException {
        Serializer subject = appFactory.serializer();
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
        Serializer subject = appFactory.serializer();
        byte[] invalidJson = "{\"iss\":\"joe\"".getBytes();

        subject.jsonBytesToObject(invalidJson, Claim.class);
    }
}