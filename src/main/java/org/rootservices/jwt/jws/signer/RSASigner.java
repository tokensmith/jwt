package org.rootservices.jwt.jws.signer;

import org.rootservices.jwt.serialization.JwtSerde;

import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64.Encoder;

/**
 * Created by tommackenzie on 11/3/15.
 */
public class RSASigner extends Signer {
    private Signature signature;

    public RSASigner(Signature signature, JwtSerde jwtSerde, Encoder encoder) {
        super(jwtSerde, encoder);
        this.signature = signature;
    }

    @Override
    public String run(byte[] input) {
        try {
            signature.update(input);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        byte[] privateKeySignature = null;
        try {
            privateKeySignature = signature.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return encode(privateKeySignature);
    }
}
