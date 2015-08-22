package org.rootservices.jwt.signer.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signer.MacSignerImpl;
import org.rootservices.jwt.signer.Signer;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class SignerFactoryImpl implements SignerFactory {
    private KeyFactory keyFactory;

    public SignerFactoryImpl(KeyFactory keyFactory){
        this.keyFactory = keyFactory;
    }

    @Override
    public Signer makeSigner(Algorithm alg, Key jwk) {
        java.security.Key securityKey = keyFactory.makeKey(alg, jwk);
        Mac mac = null;

        try {
            mac = Mac.getInstance(securityKey.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            mac.init(securityKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        Signer signer = new MacSignerImpl(mac, Base64.getUrlEncoder().withoutPadding());
        return signer;
    }
}
