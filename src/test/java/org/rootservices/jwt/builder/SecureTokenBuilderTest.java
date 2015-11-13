package org.rootservices.jwt.builder;

import helper.entity.Claim;
import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.TokenType;

import java.util.Optional;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNull;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Created by tommackenzie on 9/15/15.
 */
public class SecureTokenBuilderTest {

    private AppFactory appFactory;

    @Before
    public void setUp(){
        appFactory = new AppFactory();
    }

    /**
     * Test scenario taken from,
     * https://tools.ietf.org/html/rfc7515#appendix-A.1
     *
     * There is a modification in which the sign input does not contain line breaks
     * Which is why the signature is different than the rfc.
     *
     * @throws Exception
     */
    @Test
    public void makeSignedTokenShouldHaveValidHeaderClaimsSignature() throws Exception {

        // prepare subject of the test.
        SymmetricKey key = Factory.makeSymmetricKey();
        SecureTokenBuilder subject = appFactory.secureTokenBuilder(Algorithm.HS256, key);

        // claim of the token.
        Claim claim = Factory.makeClaim();

        Token actual = subject.build(Algorithm.HS256, claim);

        assertNotNull(actual);

        // inspect claims
        Claim actualClaim = (Claim) actual.getClaims();
        assertTrue(actualClaim.isUriIsRoot());
        assertTrue(actualClaim.getIssuer().isPresent());
        assertThat(actualClaim.getIssuer().get(), is("joe"));
        assertTrue(actualClaim.getExpirationTime().isPresent());
        assertThat(actualClaim.getExpirationTime().get(), is(1300819380L));

        // inspect header
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.HS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), is(TokenType.JWT));

        // inspect signature.
        assertTrue(actual.getSignature().isPresent());
        assertThat(actual.getSignature().get(), is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY"));

        // claims ivars that were not assigned.
        assertFalse(actualClaim.getSubject().isPresent());
        assertNull(actualClaim.getAudience());
        assertFalse(actualClaim.getNotBefore().isPresent());
        assertFalse(actualClaim.getIssuedAt().isPresent());
        assertFalse(actualClaim.getJwtId().isPresent());
    }

    /**
     * Test scenario taken from,
     * XXX
     *
     * There is a modification in which the sign input does not contain line breaks
     * And the header has the key 'typ' which is set to, 'JWT'
     *
     * Which is why the signature is different than the rfc.
     *
     * @throws Exception
     */
    @Test
    public void makeRS256SignedTokenShouldHaveValidHeaderClaimsSignature() throws Exception {

        // prepare subject of the test.
        RSAKeyPair key = Factory.makeRSAKeyPair();
        SecureTokenBuilder subject = appFactory.secureTokenBuilder(Algorithm.RS256, key);

        // claim of the token.
        Claim claim = Factory.makeClaim();

        Token actual = subject.build(Algorithm.RS256, claim);

        assertNotNull(actual);

        // inspect claims
        Claim actualClaim = (Claim) actual.getClaims();
        assertTrue(actualClaim.isUriIsRoot());
        assertTrue(actualClaim.getIssuer().isPresent());
        assertThat(actualClaim.getIssuer().get(), is("joe"));
        assertTrue(actualClaim.getExpirationTime().isPresent());
        assertThat(actualClaim.getExpirationTime().get(), is(1300819380L));

        // inspect header
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.RS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), is(TokenType.JWT));

        // inspect signature.
        assertTrue(actual.getSignature().isPresent());
        assertThat(actual.getSignature().get(), is("IDcgYnWIJ0my4FurSqfiAAbYBz2BfImT-uSqKKnk-JfncL_Nreo8Phol1KNn9fK0ZmVfcvHL-pUvVUBzI5NrJNCFMiyZWxS7msB2VKl6-jAXr9NqtVjIDyUSr_gpk51xSzHiBPVAnQn8m1Dg3dR0YkP9b5uJ70qpZ37PWOCKYAIfAhinDA77RIP9q4ImwpnJuY3IDuilDKOq9bsb6zWB8USz0PAYReqWierdS4TYAbUFrhuGZ9mPgSLRSQVtibyNTSTQYtfghYkmV9gWyCJUVwMGCM5l1xlylHYiioasBJA1Wr_NAf_sr4G8OVrW1eO01MKhijpaE8pR6DvPYNrTMQ"));

        // claims ivars that were not assigned.
        assertFalse(actualClaim.getSubject().isPresent());
        assertNull(actualClaim.getAudience());
        assertFalse(actualClaim.getNotBefore().isPresent());
        assertFalse(actualClaim.getIssuedAt().isPresent());
        assertFalse(actualClaim.getJwtId().isPresent());
    }
}