package org.rootservices.jwt.signature;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.SignerFactory;

import java.nio.charset.Charset;


/**
 * Created by tommackenzie on 8/26/15.
 *
 */
public class VerifySignatureImpl implements VerifySignature {

    private SignerFactory signerFactory;

    public VerifySignatureImpl(SignerFactory signerFactory) {
        this.signerFactory = signerFactory;
    }

    @Override
    public boolean run(Token token, Key jwk) {
        String generatedSignature = "";
        String actualSignature = "";

        if ( token.getSignature().isPresent()) {
            Signer signer = signerFactory.makeSigner(token.getHeader().getAlgorithm(), jwk);
            byte[] input = createSignInput(token.getJwt().get());
            generatedSignature = signer.run(input);
            actualSignature = token.getSignature().get();
        }
        return actualSignature.equals(generatedSignature);
    }

    private byte[] createSignInput(String input) {
        String[] inputParts = input.split("\\.");
        return (inputParts[0] + "." + inputParts[1]).getBytes(Charset.forName("UTF-8"));
    }
}
