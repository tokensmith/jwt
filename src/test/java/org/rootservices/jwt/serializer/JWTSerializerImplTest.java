package org.rootservices.jwt.serializer;

import helper.entity.Claim;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.builder.TokenBuilder;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Algorithm;

import java.util.Optional;

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.TestCase.assertEquals;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Created by tommackenzie on 8/13/15.
 */
public class JWTSerializerImplTest {

    private TokenBuilder tokenBuilder;
    private JWTSerializer subject;

    @Before
    public void setUp(){
        Key key = new Key();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        AppFactory appFactory = new AppFactory();
        tokenBuilder = appFactory.tokenBuilder(Algorithm.HS256, key);
        subject = appFactory.jwtSerializer();
    }

    @Test
    public void UnsecuredJwtToJwtStringExpectValidJWT() {

        String expectedJwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        Claim claim = new Claim();
        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);
        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        Token tokenToMarshal = tokenBuilder.makeUnsecuredToken(claim);
        String actual = subject.tokenToJwt(tokenToMarshal);
        assertEquals(actual, expectedJwt);
    }

    @Test
    public void jwtToTokenExpectUnsecuredToken() {

        String jwt = "eyJhbGciOiJub25lIn0=.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ==.";

        Token actual = subject.jwtToToken(jwt, Claim.class);
        assertNotNull(actual);

        // header
        assertNotNull(actual.getHeader());
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.NONE));

        // claim
        assertNotNull(actual.getClaimNames());
        assertThat(actual.getClaimNames(), instanceOf(Claim.class));
        assertTrue(((Claim) actual.getClaimNames()).isUriIsRoot());
        assertTrue(actual.getClaimNames().getIssuer().isPresent());
        assertThat(actual.getClaimNames().getIssuer().get(), is("joe"));
        assertTrue(actual.getClaimNames().getExpirationTime().isPresent());
        assertThat(actual.getClaimNames().getExpirationTime().get(), is(1300819380L));
        assertFalse(actual.getClaimNames().getSubject().isPresent());
        assertNull(actual.getClaimNames().getAudience());
        assertFalse(actual.getClaimNames().getNotBefore().isPresent());
        assertFalse(actual.getClaimNames().getIssuedAt().isPresent());
        assertFalse(actual.getClaimNames().getJwtId().isPresent());

        assertFalse(actual.getSignature().isPresent());
    }

}