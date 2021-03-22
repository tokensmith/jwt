package net.tokensmith.jwt.jws.serialization;

import helper.entity.Claim;
import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;

import java.io.ByteArrayOutputStream;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;



public class SecureJwtSerializerTest {
    private JwtAppFactory appFactory;

    @Before
    public void setUp() {
        appFactory = new JwtAppFactory();
    }

    @Test
    public void compactJwtWithSymmetricKeyShouldEncode() throws Exception {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKeyId(Optional.of("test-key-id"));

        Claim claim = Factory.makeClaim();

        SecureJwtSerializer subject = appFactory.secureJwtSerializer(Algorithm.HS256, key);
        ByteArrayOutputStream actual = subject.compactJwt(claim);

        assertThat(actual.toString(), is("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.YiFm03WWrDAbFn7omROmU2GHACkaGI30xdbWFzyoCNQ"));

    }

    @Test
    public void compactJwtWithAsymmetricKeyShouldEncode() throws Exception {
        RSAKeyPair key = Factory.makeRSAKeyPair();
        key.setKeyId(Optional.of("test-key-id"));

        Claim claim = Factory.makeClaim();

        SecureJwtSerializer subject = appFactory.secureJwtSerializer(Algorithm.RS256, key);
        ByteArrayOutputStream actual = subject.compactJwt(claim);

        assertThat(actual.toString(), is("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.JmMm15IjKsNB18oMqIIaIPHQ8TuqEXNdbmGyEya5Yuoo2Kj132PhiCt2gbPL2i75IH1Zmjvdc7Fm2eb2Db6P6NXezZEHgZG3WVTWJwl11lQnDnj6hTrTbHnL0XUgcFw0vIwthQF6NNjAy2lTMSG0KTH5y_3D-5pt6FM2cyfvK5RwhCom9v2MDWA7fTqR1u5L-_dfcgRlN5rjQ-QYBsk3oaNTMU9MtXtEuG7erun_-VXQJjXGwDRO_kPmzN-wILyoaOr670xpaHVmFLrTakjvfhCkLrB1YwdQV-B6ZFLqTpQpGr7ydEWMyuoiV0Xg71-mJhNHeml_jFMUwm-Lu-d2Og"));
    }

    @Test
    public void compactJwtToStringWithSymmetricKeyShouldEncode() throws Exception {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKeyId(Optional.of("test-key-id"));

        Claim claim = Factory.makeClaim();

        SecureJwtSerializer subject = appFactory.secureJwtSerializer(Algorithm.HS256, key);
        String actual = subject.compactJwtToString(claim);

        assertThat(actual, is("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.YiFm03WWrDAbFn7omROmU2GHACkaGI30xdbWFzyoCNQ"));

    }

    @Test
    public void compactJwtToStringWithAsymmetricKeyShouldEncode() throws Exception {
        RSAKeyPair key = Factory.makeRSAKeyPair();
        key.setKeyId(Optional.of("test-key-id"));

        Claim claim = Factory.makeClaim();

        SecureJwtSerializer subject = appFactory.secureJwtSerializer(Algorithm.RS256, key);
        String actual = subject.compactJwtToString(claim);

        assertThat(actual, is("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.JmMm15IjKsNB18oMqIIaIPHQ8TuqEXNdbmGyEya5Yuoo2Kj132PhiCt2gbPL2i75IH1Zmjvdc7Fm2eb2Db6P6NXezZEHgZG3WVTWJwl11lQnDnj6hTrTbHnL0XUgcFw0vIwthQF6NNjAy2lTMSG0KTH5y_3D-5pt6FM2cyfvK5RwhCom9v2MDWA7fTqR1u5L-_dfcgRlN5rjQ-QYBsk3oaNTMU9MtXtEuG7erun_-VXQJjXGwDRO_kPmzN-wILyoaOr670xpaHVmFLrTakjvfhCkLrB1YwdQV-B6ZFLqTpQpGr7ydEWMyuoiV0Xg71-mJhNHeml_jFMUwm-Lu-d2Og"));
    }
}