package org.rootservices.jwt.serializer;

import helper.entity.Claim;
import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.builder.SecureJwtBuilder;
import org.rootservices.jwt.builder.UnsecureJwtBuilder;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.TokenType;
import org.rootservices.jwt.serializer.exception.JsonToJwtException;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebKeyException;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;


/**
 * Created by tommackenzie on 8/13/15.
 */
public class JWTSerializerImplTest {

    private UnsecureJwtBuilder unsecureTokenBuilder;
    private SecureJwtBuilder secureJwtBuilder;
    private JWTSerializer subject;

    @Before
    public void setUp() throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        SymmetricKey key = Factory.makeSymmetricKey();

        AppFactory appFactory = new AppFactory();
        unsecureTokenBuilder = appFactory.unsecureJwtBuilder();
        secureJwtBuilder = appFactory.secureJwtBuilder(Algorithm.HS256, key);
        subject = appFactory.jwtSerializer();
    }

    @Test
    public void UnsecuredJwtToStringShouldBeValidJWT() throws JwtToJsonException {

        String expectedJwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        Claim claim = new Claim();
        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);
        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        JsonWebToken tokenToMarshal = unsecureTokenBuilder.build(claim);
        String actual = subject.jwtToString(tokenToMarshal);
        assertThat(actual, is(expectedJwt));
    }

    @Test
    public void SecuredJwtToStringShouldBeValid() throws JwtToJsonException {
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

        JsonWebToken tokenToMarshal = secureJwtBuilder.build(Algorithm.HS256, claim);
        String actual = subject.jwtToString(tokenToMarshal);

        assertThat(actual, is(expectedJwt));
    }

    @Test
    public void SecuredJwtWithKeyIdToStringShouldBeValid() throws JwtToJsonException {
        String signature = "YiFm03WWrDAbFn7omROmU2GHACkaGI30xdbWFzyoCNQ";

        String expectedJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        Claim claim = new Claim();
        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);
        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        JsonWebToken tokenToMarshal = secureJwtBuilder.build(Algorithm.HS256, claim, Optional.of("test-key-id"));
        String actual = subject.jwtToString(tokenToMarshal);

        assertThat(actual, is(expectedJwt));
    }

    @Test
    public void stringToJwtShouldBeUnsecuredJwt() throws JsonToJwtException {

        String jwtAsText = "eyJhbGciOiJub25lIn0=." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ==.";

        JsonWebToken actual = subject.stringToJwt(jwtAsText, Claim.class);
        assertThat(actual, is(notNullValue()));

        // header
        assertThat(actual.getHeader(), is(notNullValue()));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.NONE));
        assertThat(actual.getHeader().getKeyId().isPresent(), is(false));

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
    public void stringToJwtShouldBeSecuredJwt() throws JsonToJwtException {

        String signature = "lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        String jwtAsText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        JsonWebToken actual = subject.stringToJwt(jwtAsText, Claim.class);
        assertThat(actual, is(notNullValue()));

        // header
        assertThat(actual.getHeader(), is(notNullValue()));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.HS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), is(TokenType.JWT));
        assertThat(actual.getHeader().getKeyId().isPresent(), is(false));

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
        assertThat(actual.getJwt().get(), is(jwtAsText));
    }

    @Test
    public void stringToJwtShouldBeSecuredJwtWithKeyId() throws JsonToJwtException {

        String signature = "YiFm03WWrDAbFn7omROmU2GHACkaGI30xdbWFzyoCNQ";

        String jwtAsText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        JsonWebToken actual = subject.stringToJwt(jwtAsText, Claim.class);
        assertThat(actual, is(notNullValue()));

        // header
        assertThat(actual.getHeader(), is(notNullValue()));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.HS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), is(TokenType.JWT));
        assertThat(actual.getHeader().getKeyId().isPresent(), is(true));
        assertThat(actual.getHeader().getKeyId().get(), is("test-key-id"));

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
        assertThat(actual.getJwt().get(), is(jwtAsText));
    }
}