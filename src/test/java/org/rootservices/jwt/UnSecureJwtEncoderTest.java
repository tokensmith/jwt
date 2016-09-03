package org.rootservices.jwt;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwt.Claims;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 9/3/16.
 */
public class UnSecureJwtEncoderTest {
    private AppFactory appFactory;

    @Before
    public void setUp() {
        appFactory = new AppFactory();
    }

    @Test
    public void encodeShouldEncode() {
        UnSecureJwtEncoder subject = appFactory.unSecureJwtEncoder();

        Claims claims = Factory.makeClaim();

        String jwt = subject.encode(claims);

        assertThat(jwt, is("eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."));
    }

}