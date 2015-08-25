package org.rootservices.jwt.signer;


import javax.crypto.Mac;
import java.util.Base64.Encoder;


/**
 * Created by tommackenzie on 8/19/15.
 */
public class MacSignerImpl implements Signer {
    private Mac mac;
    private Encoder encoder;

    public MacSignerImpl(Mac mac, Encoder encoder) {
        this.mac = mac;
        this.encoder = encoder;
    }

    /**
     * Executes a message authentication code algorithm
     * Then returns its base64 encoded string value.
     *
     * See SignerFactoryImpl for details on mac and encoder.
     *
     * @param signingInput
     * @return base64 encoded signature
     */
    @Override
    public String run(byte[] signingInput) {
        byte[] signature =  mac.doFinal(signingInput);
        return encoder.encodeToString(signature);
    }
}
