package org.rootservices.jwt.serializer;


import com.fasterxml.jackson.core.JsonProcessingException;
import helper.entity.Claim;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.Algorithm;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Created by tommackenzie on 8/12/15.
 */
public class SerializerImplTest {

    private AppFactory appFactory;
    private Serializer subject;

    @Before
    public void setUp() {
        appFactory = new AppFactory();
        subject = appFactory.serializer();
    }

    @Test
    public void headerToJson() throws JsonProcessingException {
        Header header = new Header();
        header.setAlgorithm(Algorithm.NONE);
        String json = subject.objectToJson(header);
        assertThat(json, is("{\"alg\":\"none\"}"));
    }

    @Test
    public void claimToJsonExpectExcludesNullAndOptionalEmpty() throws JsonProcessingException {
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
    public void jsonToUnsecuredHeader() {
        byte[] json = "{\"alg\":\"none\"}".getBytes();
        Header actual = (Header) subject.jsonBytesToObject(json, Header.class);
        assertThat(actual.getAlgorithm(), is(Algorithm.NONE));
    }

    @Test
    public void jsonToClaim() {
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
}