package org.rootservices.jwt.signature.verifier;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.MacFactory;
import org.rootservices.jwt.signature.signer.factory.SignerFactory;


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
    public boolean run(Token token) {
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
