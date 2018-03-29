package org.rootservices.jwt.serialization;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.serialization.UnSecureJwtSerializer;
import org.rootservices.jwt.entity.jwt.Claims;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 9/3/16.
 */
public class UnSecureJwtSerializerTest {
    private JwtAppFactory appFactory;

    @Before
    public void setUp() {
        appFactory = new JwtAppFactory();
    }

    @Test
    public void encodeShouldEncode() {
        UnSecureJwtSerializer subject = appFactory.unSecureJwtEncoder();

        Claims claims = Factory.makeClaim();

        String jwt = subject.encode(claims);

        assertThat(jwt, is("eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."));
    }

}