package org.rootservices.jwt.signature.verifier;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Algorithm;

import java.nio.charset.Charset;

/**
 * Created by tommackenzie on 8/26/15.
 */
public abstract class VerifySignature {

    protected byte[] createSignInput(String input) {
        String[] inputParts = input.split("\\.");
        return (inputParts[0] + "." + inputParts[1]).getBytes(Charset.forName("UTF-8"));

    }
    abstract boolean run(Token token);
}
