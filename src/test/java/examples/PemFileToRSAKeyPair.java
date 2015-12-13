package examples;

import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.Use;
import org.rootservices.jwt.translator.PemToRSAKeyPair;
import org.rootservices.jwt.exception.InvalidKeyException;
import org.rootservices.jwt.translator.exception.InvalidPemException;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class PemFileToRSAKeyPair {

    public RSAKeyPair makeRSAKeyPair() throws MalformedURLException, FileNotFoundException, InvalidPemException, InvalidKeyException {
        AppFactory appFactory = new AppFactory();
        PemToRSAKeyPair pemToRSAKeyPair = appFactory.pemToRSAKeyPair();

        URL privateKeyURL = null;
        try {
            privateKeyURL = new URL("file:///example/rsa-private-key.pem");
        } catch (MalformedURLException e) {
            // invalid url.
            throw e;
        }

        FileReader pemFileReader = null;
        try {
            pemFileReader = new FileReader(privateKeyURL.getFile());
        } catch (FileNotFoundException e) {
            throw e;
        }

        RSAKeyPair rsaKeyPair = null;
        try {
            rsaKeyPair = pemToRSAKeyPair.translate(pemFileReader, Optional.of("test-key-id"), Use.SIGNATURE);
        } catch (InvalidPemException e) {
            // pem file could not be used.
            throw e;
        } catch (InvalidKeyException e) {
            // key in pem file could not be used.
            throw e;
        }

        return rsaKeyPair;
    }
}
