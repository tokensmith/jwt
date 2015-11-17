package org.rootservices.jwt.signature.signer;


import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.serializer.Serializer;

import javax.crypto.Mac;
import java.util.Base64.Encoder;


/**
 * Created by tommackenzie on 8/19/15.
 *
 */
public class MacSigner extends Signer {
    private Mac mac;

    public MacSigner(Serializer serializer, Mac mac, Encoder encoder) {
        super(serializer, encoder);
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
