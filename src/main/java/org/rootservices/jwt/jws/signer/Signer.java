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

    public byte[] run(JsonWebToken jwt) throws JwtToJsonException {
        byte[] signInput = jwtSerde.makeSignInput(jwt.getHeader(), jwt.getClaims());
        return run(signInput);
    }

    protected byte[] encode(byte[] input) {
        return encoder.encode(input);
    }

    public abstract byte[] run(byte[] input);
}
