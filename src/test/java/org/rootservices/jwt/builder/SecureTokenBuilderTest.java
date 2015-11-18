package org.rootservices.jwt.builder;

import helper.entity.Claim;
import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.TokenType;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;

import static org.junit.Assert.assertThat;


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

        JsonWebToken actual = subject.build(Algorithm.HS256, claim);

        assertThat(actual, is(notNullValue()));

        // inspect claims
        Claim actualClaim = (Claim) actual.getClaims();
        assertThat(actualClaim.isUriIsRoot(), is(true));
        assertThat(actualClaim.getIssuer().isPresent(), is(true));
        assertThat(actualClaim.getIssuer().get(), is("joe"));
        assertThat(actualClaim.getExpirationTime().isPresent(), is(true));
        assertThat(actualClaim.getExpirationTime().get(), is(1300819380L));

        // inspect header
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.HS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), is(TokenType.JWT));

        // inspect signature.
        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY"));

        // claims ivars that were not assigned.
        assertThat(actualClaim.getSubject().isPresent(), is(false));
        assertThat(actualClaim.getAudience(), is(nullValue()));
        assertThat(actualClaim.getNotBefore().isPresent(), is(false));
        assertThat(actualClaim.getIssuedAt().isPresent(), is(false));
        assertThat(actualClaim.getJwtId().isPresent(), is(false));
    }

    /**
     * Test scenario taken from,
     * https://tools.ietf.org/html/rfc7515#appendix-A.2
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

        JsonWebToken actual = subject.build(Algorithm.RS256, claim);

        assertThat(actual, is(notNullValue()));

        // inspect claims
        Claim actualClaim = (Claim) actual.getClaims();
        assertThat(actualClaim.isUriIsRoot(), is(true));
        assertThat(actualClaim.getIssuer().isPresent(), is(true));
        assertThat(actualClaim.getIssuer().get(), is("joe"));
        assertThat(actualClaim.getExpirationTime().isPresent(), is(true));
        assertThat(actualClaim.getExpirationTime().get(), is(1300819380L));

        // inspect header
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.RS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), is(TokenType.JWT));

        // inspect signature.
        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is("IDcgYnWIJ0my4FurSqfiAAbYBz2BfImT-uSqKKnk-JfncL_Nreo8Phol1KNn9fK0ZmVfcvHL-pUvVUBzI5NrJNCFMiyZWxS7msB2VKl6-jAXr9NqtVjIDyUSr_gpk51xSzHiBPVAnQn8m1Dg3dR0YkP9b5uJ70qpZ37PWOCKYAIfAhinDA77RIP9q4ImwpnJuY3IDuilDKOq9bsb6zWB8USz0PAYReqWierdS4TYAbUFrhuGZ9mPgSLRSQVtibyNTSTQYtfghYkmV9gWyCJUVwMGCM5l1xlylHYiioasBJA1Wr_NAf_sr4G8OVrW1eO01MKhijpaE8pR6DvPYNrTMQ"));

        // claims ivars that were not assigned.
        assertThat(actualClaim.getSubject().isPresent(), is(false));
        assertThat(actualClaim.getAudience(), is(nullValue()));
        assertThat(actualClaim.getNotBefore().isPresent(), is(false));
        assertThat(actualClaim.getIssuedAt().isPresent(), is(false));
        assertThat(actualClaim.getJwtId().isPresent(), is(false));
    }
}