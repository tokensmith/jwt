package org.rootservices.jwt.builder.compact;

import helper.entity.Claim;
import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.jws.serialization.SecureJwtSerializer;

import java.io.ByteArrayOutputStream;
import java.util.Optional;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class SecureCompactBuilderTest {
    private SecureCompactBuilder subject;

    @Before
    public void setUp() {
        subject = new SecureCompactBuilder();
    }


    @Test
    public void buildWithSymmetricKeyShouldEncode() throws Exception {
        SymmetricKey key = Factory.makeSymmetricKey();
        key.setKeyId(Optional.of("test-key-id"));

        Claim claim = Factory.makeClaim();

        ByteArrayOutputStream actual = subject.alg(Algorithm.HS256)
                .key(key)
                .claims(claim)
                .build();

        assertThat(actual.toString(), is("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.YiFm03WWrDAbFn7omROmU2GHACkaGI30xdbWFzyoCNQ"));
    }

    @Test
    public void buildWithAsymmetricKeyShouldEncode() throws Exception {
        RSAKeyPair key = Factory.makeRSAKeyPair();
        key.setKeyId(Optional.of("test-key-id"));

        Claim claim = Factory.makeClaim();

        ByteArrayOutputStream actual = subject.alg(Algorithm.RS256)
                .key(key)
                .claims(claim)
                .build();

        assertThat(actual.toString(), is("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LWlkIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.JmMm15IjKsNB18oMqIIaIPHQ8TuqEXNdbmGyEya5Yuoo2Kj132PhiCt2gbPL2i75IH1Zmjvdc7Fm2eb2Db6P6NXezZEHgZG3WVTWJwl11lQnDnj6hTrTbHnL0XUgcFw0vIwthQF6NNjAy2lTMSG0KTH5y_3D-5pt6FM2cyfvK5RwhCom9v2MDWA7fTqR1u5L-_dfcgRlN5rjQ-QYBsk3oaNTMU9MtXtEuG7erun_-VXQJjXGwDRO_kPmzN-wILyoaOr670xpaHVmFLrTakjvfhCkLrB1YwdQV-B6ZFLqTpQpGr7ydEWMyuoiV0Xg71-mJhNHeml_jFMUwm-Lu-d2Og"));
    }
}