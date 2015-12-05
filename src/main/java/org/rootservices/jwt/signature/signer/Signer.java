package org.rootservices.jwt.signature.signer;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.serializer.exception.JsonException;
import org.rootservices.jwt.serializer.Serializer;

import java.nio.charset.Charset;
import java.util.Base64.Encoder;

/**
 * Created by tommackenzie on 8/19/15.
 */
public abstract class Signer {
    private Serializer serializer;
    private Encoder encoder;

    public Signer(Serializer serializer, Encoder encoder) {
        this.serializer = serializer;
        this.encoder = encoder;
    }

    private String makeSignInput(Header header, Claims claims) {

        String headerJson = "";
        String claimsJson = "";

        try {
            headerJson = serializer.objectToJson(header);
            claimsJson = serializer.objectToJson(claims);
        } catch (JsonException e) {
            e.printStackTrace();
        }

        return encode(headerJson) + "." + encode(claimsJson);
    }

    private String encode(String input) {
        return encode(input.getBytes(Charset.forName("UTF-8")));
    }

    public String run(JsonWebToken jwt) {
        String signInput = makeSignInput(jwt.getHeader(), jwt.getClaims());
        return run(signInput.getBytes());
    }

    protected String encode(byte[] input) {
        return encoder.encodeToString(input);
    }

    public abstract String run(byte[] input);
}
