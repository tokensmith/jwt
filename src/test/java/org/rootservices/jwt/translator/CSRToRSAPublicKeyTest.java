package org.rootservices.jwt.translator;

import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.Use;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URL;
import java.util.Optional;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 12/1/15.
 */
public class CSRToRSAPublicKeyTest {
    private AppFactory appFactory;

    @Before
    public void setUp() {
        appFactory = new AppFactory();
    }

    @Test
    public void shouldTranslateCSRToRSAPublicKey() throws FileNotFoundException {
        URL privateKeyURL = getClass().getResource("/certs/rsa-cert.csr");
        FileReader fr = new FileReader(privateKeyURL.getFile());

        CSRToRSAPublicKey subject = appFactory.csrToRSAPublicKey();

        RSAPublicKey actual = subject.translate(fr, Optional.of("test-key-id"), Use.SIGNATURE);

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getKeyId().isPresent(), is(true));
        assertThat(actual.getKeyId().get(), is("test-key-id"));
        assertThat(actual.getUse(), is(Use.SIGNATURE));
        assertThat(actual.getKeyType(), is(KeyType.RSA));
        assertThat(actual.getN(), is("APnnO5dGc3kJcNRZcaOoSGHl4bcE3ew-nyZH93DYK404ct3Ty8czKGlgBe-m8DF_0R51i2hIDltHReWDBAmp7i9vysZcKr0R0Lreoi69mZk1tEM0tdyNSZg4lnYFzNJqZooaxxSmR3j9gpC8e2KG_za1xUoCdpzKVYtmoLSccrBMz_TS86W6zt-dhJMTeq9V9EfINCJ_-ICVoOsojgIvZxpJoimYLkw6Enh5SHTunaAoJMh9drg-8BipUcHlDYqamtmQ7FIGZlWVAbIffc5MqXYwFT_ehV8iCyM5yPHG-gpJpbHn1TphaAduar6LxRvYO1wNoQNqrIR5Uu_Fri5GNW0"));
        assertThat(actual.getE(), is("AQAB"));
    }

}