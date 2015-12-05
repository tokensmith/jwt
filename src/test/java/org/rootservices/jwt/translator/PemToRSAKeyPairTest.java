package org.rootservices.jwt.translator;

import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.config.DependencyException;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.Use;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URL;
import java.security.KeyPair;
import java.util.Optional;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 11/30/15.
 */
public class PemToRSAKeyPairTest {

    private AppFactory appFactory;

    @Before
    public void setUp() {
        this.appFactory = new AppFactory();
    }

    @Test
    public void shouldMakeCorrectKeyPair() throws DependencyException {

        PemToRSAKeyPair pemToRSAKeyPair = appFactory.pemToRSAKeyPair();

        URL privateKeyURL = getClass().getResource("/certs/rsa-private-key.pem");

        if (privateKeyURL == null) {
            fail("Could not find file the pem file");
        }

        FileReader pemFileReader = null;
        try {
            pemFileReader = new FileReader(privateKeyURL.getFile());
        } catch (FileNotFoundException e) {
            fail("Could not find file the pem file");
        }

        RSAKeyPair actual = pemToRSAKeyPair.translate(pemFileReader, Optional.of("test-key-id"), Use.SIGNATURE);

        assertThat(actual, is(notNullValue()));

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getKeyId().isPresent(), is(true));
        assertThat(actual.getKeyId().get(), is("test-key-id"));
        assertThat(actual.getKeyType(), is(KeyType.RSA));
        assertThat(actual.getUse(), is(Use.SIGNATURE));
        assertThat(actual.getN(), is("APnnO5dGc3kJcNRZcaOoSGHl4bcE3ew-nyZH93DYK404ct3Ty8czKGlgBe-m8DF_0R51i2hIDltHReWDBAmp7i9vysZcKr0R0Lreoi69mZk1tEM0tdyNSZg4lnYFzNJqZooaxxSmR3j9gpC8e2KG_za1xUoCdpzKVYtmoLSccrBMz_TS86W6zt-dhJMTeq9V9EfINCJ_-ICVoOsojgIvZxpJoimYLkw6Enh5SHTunaAoJMh9drg" + "-8BipUcHlDYqamtmQ7FIGZlWVAbIffc5MqXYwFT_ehV8iCyM5yPHG-gpJpbHn1TphaAduar6LxRvYO1wNoQNqrIR5Uu_Fri5GNW0"));
        assertThat(actual.getE(), is("AQAB"));
        assertThat(actual.getD(), is("AI4BiQpQXWPFKplwbjP6d48x605t9JG_j_5X3NMB89We4x8MsHp0pp0ilJz3NvxZzoJJdzt93rKd0Kk4Bv5a0t-f3hFT5HFmAz99LZnz4al_K_0YodM_cjeOyGkuqJJVJgmKZ-BjELA_Foeao158qd_z8LU6qx4zl-LMIbwgPsfQ7tExALHPcRuBr6yjyBNUA3Eh4Z8UhcwTUo1vGlICaVp3DxA1-OpgQ94xi030iIV3eyktJfakKFjKODtK4f8q1TCMD2j4afZlvvNF7Hdr_2Mk49JRsuuWoxi2eUZWNT-dTysio4iY0OCDFJtWTrvzWQlgjw_-KTald-y1UvpLqME"));
        assertThat(actual.getP(), is("AP1VQO6MlOceOe9mxB69ZmngcahoCZLfw4L7P2YS3tLITZFqlhO8IzyittX_D_pR9LbpB3nh6T0kmQjFZMT8Rh8B_z9pvfmffmxbL7uD_jk_zwGy0vb6gdbvGvn3ynGE6Xhsci7v0dZbqKNDvrCu7HNo8AFrYE_lQBQt7OPBEuXR"));
        assertThat(actual.getQ(), is("APyIvFhFEOfE_9Ssl5Z2wd7S81jDg8ZgryaWJMi032TjtrHeCbEjefq5skvb0jvSdZvwWvwsAaKdKCNjW675N53k2uRoszOBhg1Vo2HSsW8nH6J_Uh4fYPNBGEVyYj74CFcsTTDNuxfFAD_3gWpkSVocD5cbgASrKotXQTDFfNDd"));
        assertThat(actual.getDp(), is("AMqu9P5mt5OaGVwy6mJ1woSfMBA-_LnoEXKwNe8i1efqnjTkBCLR-Zc_z-yy30O1YocdNgAMASIML-xWkeMQu8F_RYqkvXwEYY-r_SqX1kRTivme6y7zCgK-1uR7nhro7iqNCWYINei8-NV3FBAkQ8Wqhat9D1ec4YHDpK4sAUSh"));
        assertThat(actual.getDq(), is("AdKW0WhGM_YHBqjsOyjGQ25wVS6sD8141iV1RIGRry-5jNUWatHfuoCGmeePP-FH-gUlEvbaWCscNA0uhzfDP_972PQsfu2rYwNAN5-Gqk-0-b5DgHYng_nvS-kEboHpxX9LW1PQyt4gH1YQ-AybPuw-7I9FQENf_jt1-_0g5n0"));
        assertThat(actual.getQi(), is("SvvKjqUWZym4xzH5r4u95csFqDhR1mN0HIjI4Z0PBfxLR82jYAusK1ocxccXay9PvGxMi8KFDrnX3GV8gRt6LUphkC6p-67vsUTUn3_M_GPRNBkio93u2qj7c3gQmuYq5AKJ6YKMMX3IjuUry4TNsIvGt50zqh5jZE1bw7_QP7w"));
    }
}