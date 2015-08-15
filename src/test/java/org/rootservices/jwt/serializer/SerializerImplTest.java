package org.rootservices.jwt.serializer;


import com.fasterxml.jackson.core.JsonProcessingException;
import helper.entity.Claim;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppConfig;
import org.rootservices.jwt.entity.header.Header;
import org.rootservices.jwt.entity.header.Algorithm;

import java.util.Optional;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNull;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Created by tommackenzie on 8/12/15.
 */
public class SerializerImplTest {

    private AppConfig appConfig;
    private Serializer subject;

    @Before
    public void setUp() {
        appConfig = new AppConfig();
        subject = appConfig.serializer();
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

        assertNotNull(actual);
        assertTrue(actual.isUriIsRoot());
        assertTrue(actual.getIssuer().isPresent());
        assertThat(actual.getIssuer().get(), is("joe"));
        assertTrue(actual.getExpirationTime().isPresent());
        assertThat(actual.getExpirationTime().get(), is(1300819380L));
        assertFalse(actual.getSubject().isPresent());
        assertNull(actual.getAudience());
        assertFalse(actual.getNotBefore().isPresent());
        assertFalse(actual.getIssuedAt().isPresent());
        assertFalse(actual.getJwtId().isPresent());

    }
}