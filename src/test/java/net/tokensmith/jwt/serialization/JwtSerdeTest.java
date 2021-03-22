package net.tokensmith.jwt.serialization;

import helper.entity.Claim;
import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.TokenType;
import net.tokensmith.jwt.factory.SecureJwtFactory;
import net.tokensmith.jwt.factory.UnSecureJwtFactory;
import org.hamcrest.core.Is;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;

import java.io.ByteArrayOutputStream;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;



public class JwtSerdeTest {

    private static JwtAppFactory appFactory = new JwtAppFactory();

    @Test
    public void UnsecuredJwtToStringShouldBeValidJWT() throws Exception {

        UnSecureJwtFactory unsecureTokenBuilder = appFactory.unsecureJwtFactory();
        JwtSerde subject = appFactory.jwtSerde();

        String expectedJwt = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.";

        Claim claim = Factory.makeClaim();

        JsonWebToken<Claim> tokenToMarshal = unsecureTokenBuilder.makeJwt(claim);
        ByteArrayOutputStream actual = subject.compactJwt(tokenToMarshal);
        assertThat(actual.toString(), is(expectedJwt));
    }

    @Test
    public void SecuredJwtToStringShouldBeValid() throws Exception {

        SymmetricKey key = Factory.makeSymmetricKey();
        SecureJwtFactory secureJwtFactory = appFactory.secureJwtFactory(Algorithm.HS256, key);
        JwtSerde subject = appFactory.jwtSerde();

        String signature = "lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        String expectedJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        Claim claim = Factory.makeClaim();

        JsonWebToken<Claim> tokenToMarshal = secureJwtFactory.makeJwt(claim);
        ByteArrayOutputStream actual = subject.compactJwt(tokenToMarshal);

        assertThat(actual.toString(), is(expectedJwt));
    }

    @Test
    public void SecuredJwtWithKeyIdToStringShouldBeValid() throws Exception {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKeyId(Optional.of("test-key-id"));

        SecureJwtFactory secureJwtFactory = appFactory.secureJwtFactory(Algorithm.HS256, key);
        JwtSerde subject = appFactory.jwtSerde();

        String signature = "YiFm03WWrDAbFn7omROmU2GHACkaGI30xdbWFzyoCNQ";

        String expectedJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        Claim claim = Factory.makeClaim();

        JsonWebToken<Claim> tokenToMarshal = secureJwtFactory.makeJwt(claim);
        ByteArrayOutputStream actual = subject.compactJwt(tokenToMarshal);

        assertThat(actual.toString(), is(expectedJwt));
    }

    @Test
    public void stringToJwtShouldBeUnsecuredJwt() throws Exception {

        JwtSerde subject = appFactory.jwtSerde();

        String jwtAsText = "eyJhbGciOiJub25lIn0=." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ==.";

        JsonWebToken<Claim> actual = subject.stringToJwt(jwtAsText, Claim.class);
        assertThat(actual, is(notNullValue()));

        // header
        assertThat(actual.getHeader(), is(notNullValue()));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.NONE));
        assertThat(actual.getHeader().getKeyId().isPresent(), is(false));

        // claim
        assertThat(actual.getClaims(), is(notNullValue()));
        assertThat(actual.getClaims(), instanceOf(Claim.class));
        assertThat((actual.getClaims()).isUriIsRoot(), is(true));
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
    public void stringToJwtShouldBeSecuredJwt() throws Exception {

        JwtSerde subject = appFactory.jwtSerde();

        String signature = "lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY";

        String jwtAsText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        JsonWebToken<Claim> actual = subject.stringToJwt(jwtAsText, Claim.class);
        assertThat(actual, is(notNullValue()));

        // header
        assertThat(actual.getHeader(), is(notNullValue()));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.HS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), Is.is(TokenType.JWT));
        assertThat(actual.getHeader().getKeyId().isPresent(), is(false));

        // claim
        assertThat(actual.getClaims(), is(notNullValue()));
        assertThat(actual.getClaims(), instanceOf(Claim.class));
        assertThat((actual.getClaims()).isUriIsRoot(), is(true));
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
        assertThat(actual.getSignature().get(), is(signature.getBytes()));

        assertThat(actual.getJwt().isPresent(), is(true));
        assertThat(actual.getJwt().get(), is(jwtAsText));
    }

    @Test
    public void stringToJwtShouldBeSecuredJwtWithKeyId() throws Exception {

        JwtSerde subject = appFactory.jwtSerde();

        String signature = "YiFm03WWrDAbFn7omROmU2GHACkaGI30xdbWFzyoCNQ";

        String jwtAsText = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                signature;

        JsonWebToken<Claim> actual = subject.stringToJwt(jwtAsText, Claim.class);
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
        assertThat((actual.getClaims()).isUriIsRoot(), is(true));
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
        assertThat(actual.getSignature().get(), is(signature.getBytes()));

        assertThat(actual.getJwt().isPresent(), is(true));
        assertThat(actual.getJwt().get(), is(jwtAsText));
    }
}