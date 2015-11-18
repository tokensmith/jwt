package org.rootservices.jwt.signature.signer;


import helper.entity.Claim;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.entity.jwt.header.TokenType;

import java.util.Optional;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 8/19/15.
 */
public class MacSignerTest {
    Signer subject;

    @Before
    public void setUp() {
        SymmetricKey key = new SymmetricKey();
        key.setKeyType(KeyType.OCT);
        key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

        AppFactory appFactory = new AppFactory();
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
    public void shouldSignTokenCorrectly() {

        // header
        Header header = new Header();
        header.setAlgorithm(Algorithm.HS256);
        header.setType(Optional.of(TokenType.JWT));

        // claim of the token.
        Claim claim = new Claim();
        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);
        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        JsonWebToken token = new JsonWebToken(header, claim);

        String actual = subject.run(token);
        assertThat(actual, is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY"));
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

        String actual = subject.run(input.getBytes());

        assertThat(actual, is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY"));
    }
}