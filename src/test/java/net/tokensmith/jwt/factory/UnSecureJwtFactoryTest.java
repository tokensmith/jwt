package net.tokensmith.jwt.factory;

import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import org.hamcrest.core.Is;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;

import helper.entity.Claim;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class UnSecureJwtFactoryTest {

    private UnSecureJwtFactory subject;

    @Before
    public void setUp(){
        JwtAppFactory appFactory = new JwtAppFactory();
        subject = appFactory.unsecureJwtFactory();
    }

    @Test
    public void makeUnsecuredTokenShouldHaveValidHeaderClaimsSignature() throws Exception {
        Claim claim = new Claim();

        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);

        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        JsonWebToken<Claim> actual = subject.makeJwt(claim);

        assertThat(actual, is(notNullValue()));

        // inspect claims
        Claim actualClaim = actual.getClaims();
        assertThat(actualClaim.isUriIsRoot(), is(true));
        assertThat(actualClaim.getIssuer().isPresent(), is(true));
        assertThat(actualClaim.getIssuer().get(), is("joe"));
        assertThat(actualClaim.getExpirationTime().isPresent(), is(true));
        assertThat(actualClaim.getExpirationTime().get(), is(1300819380L));

        // inspect header
        assertThat(actual.getHeader().getAlgorithm(), Is.is(Algorithm.NONE));

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