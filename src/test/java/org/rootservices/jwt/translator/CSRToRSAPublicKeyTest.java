package org.rootservices.jwt.translator;

import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.Use;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.math.BigInteger;
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
        assertThat(actual.getN(), is(new BigInteger("31547363068675167897756930554362079780191578737192115507526898964667457901907675194501789280350861000129589859093278343756085398379306366123730728103421370791175356895018543806044325144818946471653951140470823139449286798248410821533402163473721370921654197140946196794921284894039254456107355893831146589487500059843522247062489436603543693162592270480345794243004091939582347569432019753837113712433864529566521319428801714421137033495634109852983552061952143849954383008111368867567356581104016991597045919263898215285259909976858081430303755638022211078978491982452596141052654560597952703737488015089139469137261")));
        assertThat(actual.getE(), is(new BigInteger("65537")));
    }

}