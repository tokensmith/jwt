package org.rootservices.jwt.translator;

import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.security.KeyPair;

/**
 * Created by tommackenzie on 11/30/15.
 */
public class PemToKeyPair {

    private PEMParser pemParser;
    private JcaPEMKeyConverter converter;

    public PemToKeyPair(PEMParser pemParser, JcaPEMKeyConverter converter) {
        this.pemParser = pemParser;
        this.converter = converter;
    }

    public KeyPair translate() {
        Object pemObject = null;
        try {
            pemObject = pemParser.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        }

        KeyPair keyPair = null;
        PEMKeyPair pemKeyPair = (PEMKeyPair) pemObject;

        try {
            keyPair = converter.getKeyPair(pemKeyPair);
        } catch (PEMException e) {
            e.printStackTrace();
        }

        return keyPair;
    }
}
