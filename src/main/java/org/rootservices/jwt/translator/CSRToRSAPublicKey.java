package org.rootservices.jwt.translator;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.Use;

import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

/**
 * Created by tommackenzie on 12/1/15.
 */
public class CSRToRSAPublicKey {

    private Base64.Encoder encoder;

    public CSRToRSAPublicKey(Base64.Encoder encoder) {
        this.encoder = encoder;
    }

    public RSAPublicKey translate(FileReader csr, Optional<String> keyId, Use use) {

        PEMParser pemParser = new PEMParser(csr);
        Object obj = null;
        try {
            obj = pemParser.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        }

        PKCS10CertificationRequest certRequest = (PKCS10CertificationRequest) obj;
        JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(certRequest);

        java.security.interfaces.RSAPublicKey publicKey = null;
        try {
            publicKey = (java.security.interfaces.RSAPublicKey) jcaPKCS10CertificationRequest.getPublicKey();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return new RSAPublicKey(
                keyId,
                KeyType.RSA,
                use,
                encode(publicKey.getModulus()),
                encode(publicKey.getPublicExponent())
        );
    }

    private String encode(BigInteger value) {
        return encoder.encodeToString(value.toByteArray());
    }
}
