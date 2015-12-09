package org.rootservices.jwt.translator;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.Use;
import org.rootservices.jwt.translator.exception.InvalidKeyException;
import org.rootservices.jwt.translator.exception.InvalidCsrException;

import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * Created by tommackenzie on 12/1/15.
 */
public class CSRToRSAPublicKey {

    public RSAPublicKey translate(FileReader csr, Optional<String> keyId, Use use) throws InvalidCsrException, InvalidKeyException {

        PEMParser pemParser = new PEMParser(csr);
        PKCS10CertificationRequest certRequest = null;
        try {
            certRequest = (PKCS10CertificationRequest) pemParser.readObject();
        } catch (IOException e) {
            throw new InvalidCsrException("invalid file reader", e);
        } catch (ClassCastException e) {
            throw new InvalidCsrException("csr file is not a valid csr", e);
        }

        if (certRequest == null) {
            throw new InvalidCsrException("Could not parse the file reader");
        }

        JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(certRequest);

        java.security.interfaces.RSAPublicKey publicKey = null;
        try {
            publicKey = (java.security.interfaces.RSAPublicKey) jcaPKCS10CertificationRequest.getPublicKey();
        } catch (java.security.InvalidKeyException e) {
            throw new InvalidKeyException("RSA public key from pem file is invalid", e);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidKeyException("Could not create RSA public key", e);
        }

        return new RSAPublicKey(
                keyId,
                KeyType.RSA,
                use,
                publicKey.getModulus(),
                publicKey.getPublicExponent()
        );
    }

}
