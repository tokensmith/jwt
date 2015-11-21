package org.rootservices.jwt.builder;

import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.JsonWebToken;

import helper.entity.Claim;
import org.rootservices.jwt.entity.jwt.header.Algorithm;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class UnsecureJwtBuilderTest {

    private UnsecureJwtBuilder subject;

    @Before
    public void setUp(){
        AppFactory appFactory = new AppFactory();
        subject = appFactory.unsecureJwtBuilder();
    }

    @Test
    public void makeUnsecuredTokenShouldHaveValidHeaderClaimsSignature() throws Exception {
        Claim claim = new Claim();

        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);

        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        JsonWebToken actual = subject.build(claim);

        assertThat(actual, is(notNullValue()));

        // inspect claims
        Claim actualClaim = (Claim) actual.getClaims();
        assertThat(actualClaim.isUriIsRoot(), is(true));
        assertThat(actualClaim.getIssuer().isPresent(), is(true));
        assertThat(actualClaim.getIssuer().get(), is("joe"));
        assertThat(actualClaim.getExpirationTime().isPresent(), is(true));
        assertThat(actualClaim.getExpirationTime().get(), is(1300819380L));

        // inspect header
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.NONE));

        // inspect signature.
        assertThat(actual.getSignature().isPresent(), is(false));

        // claims ivars that were not assigned.
        assertThat(actualClaim.getSubject().isPresent(), is(false));
        assertThat(actualClaim.getAudience(), is(nullValue()));
        assertThat(actualClaim.getNotBefore().isPresent(), is(false));
        assertThat(actualClaim.getIssuedAt().isPresent(), is(false));
        assertThat(actualClaim.getJwtId().isPresent(), is(false));
    }
}