package org.rootservices.jwt.serializer;

import helper.entity.Claim;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.builder.SecureTokenBuilder;
import org.rootservices.jwt.builder.UnsecureTokenBuilder;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.TokenType;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Created by tommackenzie on 8/13/15.
 */
public class JWTSerializerImplTest {

    private UnsecureTokenBuilder unsecureTokenBuilder;
    private SecureTokenBuilder secureTokenBuilder;
    private JWTSerializer subject;

    @Before
    public void setUp(){
        SymmetricKey key = new SymmetricKey();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        AppFactory appFactory = new AppFactory();
        unsecureTokenBuilder = appFactory.unsecureTokenBuilder();
        secureTokenBuilder = appFactory.secureTokenBuilder(Algorithm.HS256, key);
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

        Token tokenToMarshal = unsecureTokenBuilder.build(claim);
        String actual = subject.tokenToJwt(tokenToMarshal);
        assertThat(actual, is(expectedJwt));
    }

    @Test
    public void SecuredJwtToJwtStringExpectValidSecureJWT() {
        String signature = "lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        String expectedJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        Claim claim = new Claim();
        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);
        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        Token tokenToMarshal = secureTokenBuilder.build(Algorithm.HS256, claim);
        String actual = subject.tokenToJwt(tokenToMarshal);

        assertThat(actual, is(expectedJwt));
    }

    @Test
    public void jwtToTokenExpectUnsecuredToken() {

        String jwt = "eyJhbGciOiJub25lIn0=." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ==.";

        Token actual = subject.jwtToToken(jwt, Claim.class);
        assertThat(actual, is(notNullValue()));

        // header
        assertThat(actual.getHeader(), is(notNullValue()));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.NONE));

        // claim
        assertThat(actual.getClaims(), is(notNullValue()));
        assertThat(actual.getClaims(), instanceOf(Claim.class));
        assertThat(((Claim) actual.getClaims()).isUriIsRoot(), is(true));
        assertThat(actual.getClaims().getIssuer().isPresent(), is(true));
        assertThat(actual.getClaims().getIssuer().get(), is("joe"));
        assertThat(actual.getClaims().getExpirationTime().isPresent(), is(true));
        assertThat(actual.getClaims().getExpirationTime().get(), is(1300819380L));
        assertThat(actual.getClaims().getSubject().isPresent(), is(false));
        assertThat(actual.getClaims().getAudience(), is(nullValue()));
        assertThat(actual.getClaims().getNotBefore().isPresent(), is(false));
        assertThat(actual.getClaims().getIssuedAt().isPresent(), is(false));
        assertThat(actual.getClaims().getJwtId().isPresent(), is(false));

        assertThat(actual.getSignature().isPresent(), is(false));
    }

    @Test
    public void jwtToTokenExpectSecuredToken() {

        String signature = "lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        Token actual = subject.jwtToToken(jwt, Claim.class);
        assertThat(actual, is(notNullValue()));

        // header
        assertThat(actual.getHeader(), is(notNullValue()));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.HS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), is(TokenType.JWT));

        // claim
        assertThat(actual.getClaims(), is(notNullValue()));
        assertThat(actual.getClaims(), instanceOf(Claim.class));
        assertThat(((Claim) actual.getClaims()).isUriIsRoot(), is(true));
        assertThat(actual.getClaims().getIssuer().isPresent(), is(true));
        assertThat(actual.getClaims().getIssuer().get(), is("joe"));
        assertThat(actual.getClaims().getExpirationTime().isPresent(), is(true));
        assertThat(actual.getClaims().getExpirationTime().get(), is(1300819380L));
        assertThat(actual.getClaims().getSubject().isPresent(), is(false));
        assertThat(actual.getClaims().getAudience(), is(nullValue()));
        assertThat(actual.getClaims().getNotBefore().isPresent(), is(false));
        assertThat(actual.getClaims().getIssuedAt().isPresent(), is(false));
        assertThat(actual.getClaims().getJwtId().isPresent(), is(false));

        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is(signature));

        assertThat(actual.getJwt().isPresent(), is(true));
        assertThat(actual.getJwt().get(), is(jwt));
    }


}