package org.rootservices.jwt.jws.signer;


import org.rootservices.jwt.serialization.JWTDeserializer;

import javax.crypto.Mac;
import java.util.Base64.Encoder;


/**
 * Created by tommackenzie on 8/19/15.
 *
 */
public class MacSigner extends Signer {
    private Mac mac;

    public MacSigner(JWTDeserializer jwtDeserializer, Mac mac, Encoder encoder) {
        super(jwtDeserializer, encoder);
        this.mac = mac;
    }

    @Override
    public String run(byte[] input) {
        return sign(input);
    }

    private String sign(byte[] input) {
        byte[] signature = mac.doFinal(input);
        return encode(signature);
    }
}
