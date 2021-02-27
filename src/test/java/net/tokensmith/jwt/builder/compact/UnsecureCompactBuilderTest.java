package net.tokensmith.jwt.builder.compact;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwt.Claims;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;


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