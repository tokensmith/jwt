package org.rootservices.jwt.translator;

import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.Use;
import org.rootservices.jwt.translator.exception.InvalidPemException;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
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

    private FileReader makeFileReader(String filePath) {

        URL privateKeyURL = getClass().getResource(filePath);

        if (privateKeyURL == null) {
            fail("Could not find file the pem file");
        }

        FileReader pemFileReader = null;
        try {
            pemFileReader = new FileReader(privateKeyURL.getFile());
        } catch (FileNotFoundException e) {
            fail("Could not find file the pem file");
        }

        return pemFileReader;
    }

    @Test
    public void shouldMakeCorrectKeyPair() throws InvalidPemException {

        PemToRSAKeyPair pemToRSAKeyPair = appFactory.pemToRSAKeyPair();

        FileReader pemFileReader = makeFileReader("/certs/rsa-private-key.pem");

        // expected
        BigInteger modulus = new BigInteger("31547363068675167897756930554362079780191578737192115507526898964667457901907675194501789280350861000129589859093278343756085398379306366123730728103421370791175356895018543806044325144818946471653951140470823139449286798248410821533402163473721370921654197140946196794921284894039254456107355893831146589487500059843522247062489436603543693162592270480345794243004091939582347569432019753837113712433864529566521319428801714421137033495634109852983552061952143849954383008111368867567356581104016991597045919263898215285259909976858081430303755638022211078978491982452596141052654560597952703737488015089139469137261");
        BigInteger publicExponent = new BigInteger("65537");
        BigInteger privateExponent = new BigInteger("17926596396547475894233270530768851383098319785033974298729103320920713485892606190677649794612912011624365716198373114421172411325567975049420267105597071419719570107380343773454639558084782421393484511379433366437751036110427199974448479025967889505063154488700692964884928677524388897872866332639054734563540603538126904942970545933364201807568104872067768314855737491966908061964979181796120872344579985695190632663663576855846805589958978811239981840087025695582715666984680745947985390068749640688608533968405297323218578662269674742653843895867705344639568613274268304462852744075002084615909877427512082671809");
        BigInteger primeP = new BigInteger("177896497866913720666018635152384129022597163894037528397616765963660310944144586061003646473127224648491803487187299104582675895481985461698392379397626497276548015737035578624405241545087536057660433797241365357543813340937549961569784412712933089949857152189846777292464517821447558299649089116062107231697");
        BigInteger primeQ = new BigInteger("177335492530471784736855608763756232554907628078583812409958753247718335607210292037747143084156694233415555712874052909486016311004636559265753924014644550889364310406206169714329162148665359467600692075303825823321048442016831954507581831805295679970247348504587073016601516999984331832595091571024265531613");
        BigInteger primeExponentP = new BigInteger("142329141845884828866167525452494154770142967966491657598007804851283469552241897333150208266657810049575342540048809699096510793959174599061499702783696961383623276273795314548912285200346672347641289435350317395630747649705044397591438056306970621762223017805551458268658689403692284844954763549012016579745");
        BigInteger primeExponentQ = new BigInteger("1279882935851704444520388527782118467407286083909396879166127382794006023196216917677867444021028066167288064027792346707766387156952455750685896608922087867474393378124349882888714675623216122620430098289801327714586507058210804804646019903930678191341181253988886972807002419106651036159993260495513642621");
        BigInteger crtCoefficient = new BigInteger("52655246168149931266593527226554483262446108013405644846090346118573657005660216425771053079024891453912366463810544032383603524938201963417881747736294434635848257983482194424189814343462587544169753320024624881614416412658658522200837842119558010863255094195173449128914773351492908487605687200685726121916");

        RSAKeyPair actual = pemToRSAKeyPair.translate(pemFileReader, Optional.of("test-key-id"), Use.SIGNATURE);

        assertThat(actual, is(notNullValue()));

        assertThat(actual, is(notNullValue()));
        assertThat(actual.getKeyId().isPresent(), is(true));
        assertThat(actual.getKeyId().get(), is("test-key-id"));
        assertThat(actual.getKeyType(), is(KeyType.RSA));
        assertThat(actual.getUse(), is(Use.SIGNATURE));

        assertThat(actual.getN(), is(modulus));
        assertThat(actual.getE(), is(publicExponent));
        assertThat(actual.getD(), is(privateExponent));
        assertThat(actual.getP(), is(primeP));
        assertThat(actual.getQ(), is(primeQ));
        assertThat(actual.getDp(), is(primeExponentP));
        assertThat(actual.getDq(), is(primeExponentQ));
        assertThat(actual.getQi(), is(crtCoefficient));
    }

    @Test(expected = InvalidPemException.class)
    public void closedFileReaderShouldThrowInvalidPemException() throws InvalidPemException, IOException {
        PemToRSAKeyPair pemToRSAKeyPair = appFactory.pemToRSAKeyPair();

        FileReader pemFileReader = makeFileReader("/certs/rsa-private-key.pem");
        pemFileReader.close();

        pemToRSAKeyPair.translate(pemFileReader, Optional.of("test-key-id"), Use.SIGNATURE);
    }

    @Test(expected = InvalidPemException.class)
    public void emptyPemFileShouldThrowInvalidPemException() throws InvalidPemException {
        PemToRSAKeyPair pemToRSAKeyPair = appFactory.pemToRSAKeyPair();

        FileReader pemFileReader = makeFileReader("/certs/rsa-private-key-bad.pem");
        pemToRSAKeyPair.translate(pemFileReader, Optional.of("test-key-id"), Use.SIGNATURE);
    }

    @Test(expected = InvalidPemException.class)
    public void csrFileShouldThrowInvalidPemException() throws InvalidPemException {
        PemToRSAKeyPair pemToRSAKeyPair = appFactory.pemToRSAKeyPair();

        FileReader pemFileReader = makeFileReader("/certs/rsa-cert.csr");
        pemToRSAKeyPair.translate(pemFileReader, Optional.of("test-key-id"), Use.SIGNATURE);
    }



}