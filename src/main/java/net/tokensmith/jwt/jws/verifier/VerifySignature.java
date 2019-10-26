package net.tokensmith.jwt.jws.verifier;

import net.tokensmith.jwt.entity.jwt.JsonWebToken;

import java.nio.charset.Charset;

/**
 * Created by tommackenzie on 8/26/15.
 */
public abstract class VerifySignature {

    protected byte[] createSignInput(String input) {
        String[] inputParts = input.split("\\.");
        return (inputParts[0] + "." + inputParts[1]).getBytes(Charset.forName("UTF-8"));

    }
    public abstract boolean run(JsonWebToken token);
}
