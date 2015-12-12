package examples;

import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.Use;
import org.rootservices.jwt.translator.CSRToRSAPublicKey;
import org.rootservices.jwt.translator.exception.InvalidCsrException;
import org.rootservices.jwt.translator.exception.InvalidKeyException;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class CSRFileToRSAPublicKey {

    public RSAPublicKey toRSAPublicKey() throws MalformedURLException, FileNotFoundException, InvalidCsrException, InvalidKeyException {
        AppFactory appFactory = new AppFactory();
        CSRToRSAPublicKey csrToRSAPublicKey = appFactory.csrToRSAPublicKey();

        URL privateKeyURL = null;
        try {
            privateKeyURL = new URL("file:///example/rsa-cert.csr");
        } catch (MalformedURLException e) {
            // invalid url.
            throw e;
        }

        FileReader fr = null;
        try {
            fr = new FileReader(privateKeyURL.getFile());
        } catch (FileNotFoundException e) {
            throw e;
        }

        RSAPublicKey rsaPublicKey = null;
        try {
            rsaPublicKey = csrToRSAPublicKey.translate(fr, Optional.of("test-key-id"), Use.SIGNATURE);
        } catch (InvalidCsrException e) {
            // csr file could not be used.
            throw e;
        } catch (InvalidKeyException e) {
            // key in the csr file could not be used.
            throw e;
        }

        return rsaPublicKey;
    }
}
