package net.tokensmith.jwt.jws.signer;


import net.tokensmith.jwt.serialization.JwtSerde;

import javax.crypto.Mac;
import java.util.Base64.Encoder;


/**
 * Created by tommackenzie on 8/19/15.
 *
 */
public class MacSigner extends Signer {
    private Mac mac;

    public MacSigner(JwtSerde jwtSerde, Mac mac, Encoder encoder) {
        super(jwtSerde, encoder);
        this.mac = mac;
    }

    @Override
    public byte[] run(byte[] input) {
        return sign(input);
    }

    private byte[] sign(byte[] input) {
        byte[] signature = mac.doFinal(input);
        return encode(signature);
    }
}
