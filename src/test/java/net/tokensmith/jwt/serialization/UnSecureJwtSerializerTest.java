package net.tokensmith.jwt.serialization;

import helper.entity.Factory;
import net.tokensmith.jwt.entity.jwt.Claims;
import org.junit.Before;
import org.junit.Test;
import net.tokensmith.jwt.config.JwtAppFactory;

import java.io.ByteArrayOutputStream;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;


public class UnSecureJwtSerializerTest {
    private JwtAppFactory appFactory;

    @Before
    public void setUp() {
        appFactory = new JwtAppFactory();
    }

    @Test
    public void compactJwtShouldBeOk() {
        UnSecureJwtSerializer subject = appFactory.unSecureJwtSerializer();

        Claims claims = Factory.makeClaim();

        ByteArrayOutputStream actual = subject.compactJwt(claims);

        assertThat(actual.toString(), is("eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."));
    }

    @Test
    public void compactJwtToStringShouldBeOk() {
        UnSecureJwtSerializer subject = appFactory.unSecureJwtSerializer();

        Claims claims = Factory.makeClaim();

        String jwt = subject.compactJwtToString(claims);

        assertThat(jwt, is("eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."));
    }

}