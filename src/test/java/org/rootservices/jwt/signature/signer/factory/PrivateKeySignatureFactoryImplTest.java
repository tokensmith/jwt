package org.rootservices.jwt.signature.signer.factory;

import helper.entity.Factory;
import org.junit.Before;
import org.junit.Test;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.rsa.PrivateKeySignatureFactory;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.PrivateKeyException;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.RSAPrivateKeyException;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;

/**
 * Created by tommackenzie on 11/6/15.
 */
public class PrivateKeySignatureFactoryImplTest {

    private PrivateKeySignatureFactory subject;

    @Before
    public void setUp() {
        AppFactory appFactory = new AppFactory();
        this.subject = appFactory.privateKeySignatureFactory();
    }

    @Test
    public void makePrivateKeyShouldMakeRSAPrivateCrtKey() throws Exception {
        RSAKeyPair jwk = Factory.makeRSAKeyPair();
        RSAPrivateCrtKey privateKey = subject.makePrivateKey(jwk);

        // expected values
        BigInteger modulus = new BigInteger("20446702916744654562596343388758805860065209639960173505037453331270270518732245089773723012043203236097095623402044690115755377345254696448759605707788965848889501746836211206270643833663949992536246985362693736387185145424787922241585721992924045675229348655595626434390043002821512765630397723028023792577935108185822753692574221566930937805031155820097146819964920270008811327036286786392793593121762425048860211859763441770446703722015857250621107855398693133264081150697423188751482418465308470313958250757758547155699749157985955379381294962058862159085915015369381046959790476428631998204940879604226680285601");
        BigInteger publicExponent = new BigInteger("65537");
        BigInteger privateExponent = new BigInteger("2358310989939619510179986262349936882924652023566213765118606431955566700506538911356936879137503597382515919515633242482643314423192704128296593672966061810149316320617894021822784026407461403384065351821972350784300967610143459484324068427674639688405917977442472804943075439192026107319532117557545079086537982987982522396626690057355718157403493216553255260857777965627529169195827622139772389760130571754834678679842181142252489617665030109445573978012707793010592737640499220015083392425914877847840457278246402760955883376999951199827706285383471150643561410605789710883438795588594095047409018233862167884701");
        BigInteger primeP = new BigInteger("157377055902447438395586165028960291914931973278777532798470200156035267537359239071829408411909323208574959800537247728959718236884809685233284537349207654661530801859889389455120932077199406250387226339056140578989122526711937239401762061949364440402067108084155200696015505170135950332209194782224750221639");
        BigInteger primeQ = new BigInteger("129921752567406358990993347540064445018230073402482260994179328573323861908379211274626956543471664997237185298964648133324343327052852264060322088122401124781249085873464824282666514908127141915943024862618996371026577302203267804867959037802770797169483022132210859867700312376409633383772189122488119155159");
        BigInteger primeExponentP = new BigInteger("4922760648183732070600601771661330216909692924935440167185924139339187000497222028735680413269055839870281941362914961691371628021024152077883230870590287807744299308982303864732867094286567630701646611762288298013758658158894538059014178662376933683632720014228880806671525788467258162275185762295508460173");
        BigInteger primeExponentQ = new BigInteger("95501022448116849078110281587424883261489167280943290677534750975651978631525094586933777934986404467352856624385049043666431411835209194330560695076194390729082708437497817187133629692908081460223069101908960299950170666285307890683263785145958472051553704139602453015343925544671829327400421727981791235189");
        BigInteger crtCoefficient = new BigInteger("23545019917990284444784037831882732213707743418529123971725460465297450415859883707284136179135646366158633580054594447195052813412945775933274620822213099556720089770059982091144435545976515508108465724188242241967967709555336331874325396876783846248039429242763646988988076187339075374375350105207330456437");

        assertThat(privateKey, is(notNullValue()));
        assertThat(privateKey.getAlgorithm(), is("RSA"));
        assertThat(privateKey.getModulus(), is(modulus));
        assertThat(privateKey.getPublicExponent(), is(publicExponent));
        assertThat(privateKey.getPrivateExponent(), is(privateExponent));
        assertThat(privateKey.getPrimeP(), is(primeP));
        assertThat(privateKey.getPrimeQ(), is(primeQ));
        assertThat(privateKey.getPrimeExponentP(), is(primeExponentP));
        assertThat(privateKey.getPrimeExponentQ(), is(primeExponentQ));
        assertThat(privateKey.getCrtCoefficient(), is(crtCoefficient));
    }

    @Test(expected = PrivateKeyException.class)
    public void makePrivateKeyWhenKeyIsNot512ShouldThrowPrivateKeyException() throws Exception {
        RSAKeyPair rsaKeyPair = Factory.makeRSAKeyPair();
        rsaKeyPair.setN(new BigInteger("12"));

        subject.makePrivateKey(rsaKeyPair);
    }

    @Test
    public void testMakeSignatureShouldBeRS256() throws InvalidAlgorithmException, PrivateKeyException, RSAPrivateKeyException {
        RSAKeyPair jwk = Factory.makeRSAKeyPair();
        Signature signature = subject.makeSignature(Algorithm.RS256, jwk);

        assertThat(signature.getAlgorithm(), is(SignAlgorithm.RS256.getValue()));
    }
}