package net.tokensmith.jwt.jws.signer;


import helper.entity.Claim;
import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.Header;
import net.tokensmith.jwt.entity.jwt.header.TokenType;
import net.tokensmith.jwt.serialization.exception.JwtToJsonException;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;


import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;


/**
 * Created by tommackenzie on 8/19/15.
 */
public class MacSignerTest {
    Signer subject;

    @Before
    public void setUp() throws Exception {
        SymmetricKey key = Factory.makeSymmetricKey();

        JwtAppFactory appFactory = new JwtAppFactory();
        subject = appFactory.signerFactory().makeSigner(Algorithm.HS256, key);
    }

    /**
     * Test scenario taken from,
     * https://tools.ietf.org/html/rfc7515#appendix-A.1
     *
     * There is a modification in which the sign input does not contain \r\n
     * Which is why the signature is different than the rfc.
     */
    @Test
    public void shouldSignJwtCorrectly() throws JwtToJsonException {

        // header
        Header header = new Header();
        header.setAlgorithm(Algorithm.HS256);
        header.setType(Optional.of(TokenType.JWT));

        // claim of the jwt.
        Claim claim = new Claim();
        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);
        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        JsonWebToken<Claim> jwt = new JsonWebToken<>(header, claim);

        byte[] actual = subject.run(jwt);
        assertThat(actual, is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY".getBytes()));
    }

    /**
     * Test scenario taken from,
     * https://tools.ietf.org/html/rfc7515#appendix-A.1
     *
     * There is a modification in which the sign input does not contain \r\n
     * Which is why the signature is different than the rfc.
     */
    @Test
    public void shouldSignBytesCorrectly() {
        String input = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

        byte[] actual = subject.run(input.getBytes());

        assertThat(actual, is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY".getBytes()));
    }
}