package net.tokensmith.jwt.factory;

import helper.entity.Claim;
import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.TokenType;
import net.tokensmith.jwt.serialization.exception.JwtToJsonException;
import org.hamcrest.core.Is;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;

import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.Is.is;

import static org.junit.Assert.assertThat;



public class SecureJwtFactoryTest {

    private JwtAppFactory appFactory;

    @Before
    public void setUp(){
        appFactory = new JwtAppFactory();
    }


    @Test
    public void constructShouldAssignIVars() throws Exception {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKeyId(Optional.of("test-key-id"));
        SecureJwtFactory subject = appFactory.secureJwtFactory(Algorithm.HS256, key);

        assertThat(subject.getAlgorithm(), is(Algorithm.HS256));
        assertThat(subject.getKeyId().isPresent(), is(true));
        assertThat(subject.getKeyId(), is(key.getKeyId()));

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
    public void buildWithSymmetricKeyShouldHaveValidHeaderClaimsSignature() throws Exception {

        // prepare subject of the test.
        SymmetricKey key = Factory.makeSymmetricKey();
        SecureJwtFactory subject = appFactory.secureJwtFactory(Algorithm.HS256, key);

        // claim of the token.
        Claim claim = Factory.makeClaim();

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
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.HS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), Is.is(TokenType.JWT));
        assertThat(actual.getHeader().getKeyId().isPresent(), is(false));

        // inspect signature.
        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY".getBytes()));

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
    public void buildWithRSAKeyPairShouldHaveValidHeaderClaimsSignature() throws Exception {

        // prepare subject of the test.
        RSAKeyPair key = Factory.makeRSAKeyPair();
        SecureJwtFactory subject = appFactory.secureJwtFactory(Algorithm.RS256, key);

        // claim of the token.
        Claim claim = Factory.makeClaim();

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
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.RS256));
        assertThat(actual.getHeader().getType().isPresent(), is(true));
        assertThat(actual.getHeader().getType().get(), is(TokenType.JWT));
        assertThat(actual.getHeader().getKeyId().isPresent(), is(false));

        // inspect signature.
        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is("IDcgYnWIJ0my4FurSqfiAAbYBz2BfImT-uSqKKnk-JfncL_Nreo8Phol1KNn9fK0ZmVfcvHL-pUvVUBzI5NrJNCFMiyZWxS7msB2VKl6-jAXr9NqtVjIDyUSr_gpk51xSzHiBPVAnQn8m1Dg3dR0YkP9b5uJ70qpZ37PWOCKYAIfAhinDA77RIP9q4ImwpnJuY3IDuilDKOq9bsb6zWB8USz0PAYReqWierdS4TYAbUFrhuGZ9mPgSLRSQVtibyNTSTQYtfghYkmV9gWyCJUVwMGCM5l1xlylHYiioasBJA1Wr_NAf_sr4G8OVrW1eO01MKhijpaE8pR6DvPYNrTMQ".getBytes()));

        // claims ivars that were not assigned.
        assertThat(actualClaim.getSubject().isPresent(), is(false));
        assertThat(actualClaim.getAudience(), is(nullValue()));
        assertThat(actualClaim.getNotBefore().isPresent(), is(false));
        assertThat(actualClaim.getIssuedAt().isPresent(), is(false));
        assertThat(actualClaim.getJwtId().isPresent(), is(false));
    }

    @Test
    public void buildWithRSAKeyPairAndKeyId() throws JwtToJsonException, InvalidAlgorithmException, InvalidJsonWebKeyException {
        Optional<String> keyId = Optional.of("test-key-id");

        // prepare subject of the test.
        RSAKeyPair key = Factory.makeRSAKeyPair();
        key.setKeyId(keyId);

        SecureJwtFactory subject = appFactory.secureJwtFactory(Algorithm.RS256, key);

        // claim of the token.
        Claim claim = Factory.makeClaim();

        JsonWebToken<Claim> actual = subject.makeJwt(claim);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getHeader().getKeyId(), is(keyId));
        assertThat(actual.getHeader().getAlgorithm(), is(Algorithm.RS256));
    }

    @Test
    public void buildTwiceWithRSAKeyPairShouldSignsCorrectly() throws JwtToJsonException, InvalidAlgorithmException, InvalidJsonWebKeyException {

        // prepare subject of the test.
        RSAKeyPair key = Factory.makeRSAKeyPair();
        SecureJwtFactory subject = appFactory.secureJwtFactory(Algorithm.RS256, key);

        // claim of the token.
        Claim claim = Factory.makeClaim();

        // first JsonWebToken.
        JsonWebToken<Claim> actual = subject.makeJwt(claim);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is("IDcgYnWIJ0my4FurSqfiAAbYBz2BfImT-uSqKKnk-JfncL_Nreo8Phol1KNn9fK0ZmVfcvHL-pUvVUBzI5NrJNCFMiyZWxS7msB2VKl6-jAXr9NqtVjIDyUSr_gpk51xSzHiBPVAnQn8m1Dg3dR0YkP9b5uJ70qpZ37PWOCKYAIfAhinDA77RIP9q4ImwpnJuY3IDuilDKOq9bsb6zWB8USz0PAYReqWierdS4TYAbUFrhuGZ9mPgSLRSQVtibyNTSTQYtfghYkmV9gWyCJUVwMGCM5l1xlylHYiioasBJA1Wr_NAf_sr4G8OVrW1eO01MKhijpaE8pR6DvPYNrTMQ".getBytes()));

        // second JsonWebToken
        actual = subject.makeJwt(claim);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is("IDcgYnWIJ0my4FurSqfiAAbYBz2BfImT-uSqKKnk-JfncL_Nreo8Phol1KNn9fK0ZmVfcvHL-pUvVUBzI5NrJNCFMiyZWxS7msB2VKl6-jAXr9NqtVjIDyUSr_gpk51xSzHiBPVAnQn8m1Dg3dR0YkP9b5uJ70qpZ37PWOCKYAIfAhinDA77RIP9q4ImwpnJuY3IDuilDKOq9bsb6zWB8USz0PAYReqWierdS4TYAbUFrhuGZ9mPgSLRSQVtibyNTSTQYtfghYkmV9gWyCJUVwMGCM5l1xlylHYiioasBJA1Wr_NAf_sr4G8OVrW1eO01MKhijpaE8pR6DvPYNrTMQ".getBytes()));

    }

    @Test
    public void buildTwiceWithSymmetricKeyShouldSignsCorrectly() throws Exception {

        // prepare subject of the test.
        SymmetricKey key = Factory.makeSymmetricKey();
        SecureJwtFactory subject = appFactory.secureJwtFactory(Algorithm.HS256, key);

        // claim of the token.
        Claim claim = Factory.makeClaim();

        // first JsonWebToken.
        JsonWebToken<Claim> actual = subject.makeJwt(claim);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY".getBytes()));

        // second JsonWebToken
        actual = subject.makeJwt(claim);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getSignature().isPresent(), is(true));
        assertThat(actual.getSignature().get(), is("lliDzOlRAdGUCfCHCPx_uisb6ZfZ1LRQa0OJLeYTTpY".getBytes()));

    }
}