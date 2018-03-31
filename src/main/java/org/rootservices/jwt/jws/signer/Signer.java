package org.rootservices.jwt.jws.signer;

import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.serialization.JwtSerde;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

import java.nio.charset.Charset;
import java.util.Base64.Encoder;

/**
 * Created by tommackenzie on 8/19/15.
 */
public abstract class Signer {
    private JwtSerde jwtSerde;
    private Encoder encoder;

    public Signer(JwtSerde jwtSerde, Encoder encoder) {
        this.jwtSerde = jwtSerde;
        this.encoder = encoder;
    }

    private String encode(String input) {
        return encode(input.getBytes(Charset.forName("UTF-8")));
    }

    public String run(JsonWebToken jwt) throws JwtToJsonException {
        String signInput = jwtSerde.makeSignInput(jwt.getHeader(), jwt.getClaims());
        return run(signInput.getBytes());
    }

    protected String encode(byte[] input) {
        return encoder.encodeToString(input);
    }

    public abstract String run(byte[] input);
}
