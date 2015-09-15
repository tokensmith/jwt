package org.rootservices.jwt.builder;

import helper.entity.Claim;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
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

    private SecureTokenBuilder subject;

    @Before
    public void setUp(){
        Key key = new Key();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        AppFactory appFactory = new AppFactory();
        subject = appFactory.secureTokenBuilder(Algorithm.HS256, key);
    }

    /**
     * Test scenario taken from,
     * https://tools.ietf.org/html/rfc7515#appendix-A.1
     *
     * There is a modification in which the sign input does not contain \r\n
     * Which is why the signature is different than the rfc.
     *
     * @throws Exception
     */
    @Test
    public void makeSignedTokenShouldHaveValidHeaderClaimsSignature() throws Exception {

        // claim of the token.
        Claim claim = new Claim();
        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);
        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

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
        assertThat(actual.getHeader().getType(), is(TokenType.JWT));

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
}