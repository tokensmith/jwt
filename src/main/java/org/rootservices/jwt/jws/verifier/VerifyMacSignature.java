package org.rootservices.jwt.jws.verifier;

import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.jws.signer.Signer;


/**
 * Created by tommackenzie on 8/26/15.
 *
 */
public class VerifyMacSignature extends VerifySignature {

    private Signer macSigner;

    public VerifyMacSignature(Signer macSigner) {
        this.macSigner = macSigner;
    }

    @Override
    public boolean run(JsonWebToken token) {
        String generatedSignature = "";
        String actualSignature = "";

        if ( token.getSignature().isPresent()) {
            byte[] input = createSignInput(token.getJwt().get());
            generatedSignature = macSigner.run(input);
            actualSignature = token.getSignature().get();
        }
        return actualSignature.equals(generatedSignature);
    }
}
