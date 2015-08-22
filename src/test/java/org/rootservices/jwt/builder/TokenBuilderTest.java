package org.rootservices.jwt.builder;

import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.entity.jwt.Token;

import helper.entity.Claim;
import org.rootservices.jwt.entity.jwt.header.Algorithm;

import java.util.Optional;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNull;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class TokenBuilderTest {

    private TokenBuilder subject;

    @Before
    public void setUp(){
        subject = new TokenBuilder();
    }

    @Test
    public void testMakeUnsecuredToken() throws Exception {
        Claim claim = new Claim();

        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);

        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        Token actual = subject.makeUnsecuredToken(claim);

        assertNotNull(actual);

        // inspect claims
        Claim actualClaim = (Claim) actual.getClaimNames();
        assertTrue(actualClaim.isUriIsRoot());
        assertTrue(actualClaim.getIssuer().isPresent());
        assertThat(actualClaim.getIssuer().get(), is("joe"));
        assertTrue(actualClaim.getExpirationTime().isPresent());
        assertThat(actualClaim.getExpirationTime().get(), is(1300819380L));

        // inspect header
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.NONE));

        // inspect signature.
        assertFalse(actual.getSignature().isPresent());

        // claims ivars that were not assigned.
        assertFalse(actualClaim.getSubject().isPresent());
        assertNull(actualClaim.getAudience());
        assertFalse(actualClaim.getNotBefore().isPresent());
        assertFalse(actualClaim.getIssuedAt().isPresent());
        assertFalse(actualClaim.getJwtId().isPresent());
    }
}