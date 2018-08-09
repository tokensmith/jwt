package org.rootservices.jwt.builder.compact;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.serialization.UnSecureJwtSerializer;

import java.io.ByteArrayOutputStream;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

public class UnsecureCompactBuilderTest {
    private UnsecureCompactBuilder subject;

    @Before
    public void setUp() {
        subject = new UnsecureCompactBuilder();
    }

    @Test
    public void buildShouldBeOk() {

        Claims claims = Factory.makeClaim();

        ByteArrayOutputStream actual = subject.claims(claims).build();
        assertThat(actual.toString(), is("eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."));
    }
}