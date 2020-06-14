package net.tokensmith.jwt.jws.verifier;

import net.tokensmith.jwt.entity.jwt.Claims;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;

import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class VerifyRsaSignature extends VerifySignature {
    private Signature signature;
    private Base64.Decoder decoder;

    public VerifyRsaSignature(Signature signature, Base64.Decoder decoder) {
        this.signature = signature;
        this.decoder = decoder;
    }

    @Override
    public <T extends Claims> boolean run(JsonWebToken<T> token) {

        boolean isVerified = false;

        byte[] signInput = createSignInput(token.getJwt().get());
        try {
            signature.update(signInput);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        byte[] decodedSignature = decoder.decode(token.getSignature().get());

        try {
            isVerified = signature.verify(decodedSignature);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        return isVerified;
    }
}
