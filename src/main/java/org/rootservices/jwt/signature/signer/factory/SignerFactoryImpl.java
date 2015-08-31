package org.rootservices.jwt.signature.signer.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.Serializer;
import org.rootservices.jwt.signature.signer.MacSignerImpl;
import org.rootservices.jwt.signature.signer.Signer;


import javax.crypto.Mac;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/22/15.
 */
public class SignerFactoryImpl implements SignerFactory {
    private MacFactory macFactory;
    private Serializer serializer;
    private Base64.Encoder encoder;

    public SignerFactoryImpl(MacFactory macFactory, Serializer serializer, Base64.Encoder encoder){
        this.macFactory = macFactory;
        this.serializer = serializer;
        this.encoder = encoder;
    }

    @Override
    public Signer makeSigner(Algorithm alg, Key jwk) {
        Mac mac = macFactory.makeMac(alg, jwk);

        Signer signer = new MacSignerImpl(
                serializer,
                mac,
                encoder
        );
        return signer;
    }
}
