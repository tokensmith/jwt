package net.tokensmith.jwt.jws.verifier;

import net.tokensmith.jwt.entity.jwt.Claims;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.jws.signer.Signer;

import java.util.Arrays;



public class VerifyMacSignature extends VerifySignature {

    private Signer macSigner;

    public VerifyMacSignature(Signer macSigner) {
        this.macSigner = macSigner;
    }

    @Override
    public <T extends Claims> boolean run(JsonWebToken<T> token) {
        byte[] generatedSignature = null;
        byte[] actualSignature = null;

        if ( token.getSignature().isPresent()) {
            byte[] input = createSignInput(token.getJwt().get());
            generatedSignature = macSigner.run(input);
            actualSignature = token.getSignature().get();
        }
        return Arrays.equals(actualSignature, generatedSignature);
    }
}
