package org.rootservices.jwt.signature.signer;


import com.fasterxml.jackson.core.JsonProcessingException;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.serializer.Serializer;

import javax.crypto.Mac;
import java.nio.charset.Charset;
import java.util.Base64.Encoder;


/**
 * Created by tommackenzie on 8/19/15.
 *
 */
public class MacSignerImpl implements Signer {
    private Serializer serializer;
    private Mac mac;
    private Encoder encoder;

    public MacSignerImpl(Serializer serializer, Mac mac, Encoder encoder) {
        this.serializer = serializer;
        this.mac = mac;
        this.encoder = encoder;
    }

    @Override
    public String run(Token token) {

        String headerJson = "";
        String claimsJson = "";

        try {
            headerJson = serializer.objectToJson(token.getHeader());
            claimsJson = serializer.objectToJson(token.getClaims());
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        String signInput = encode(headerJson) + "." + encode(claimsJson);
        return sign(signInput.getBytes());
    }

    @Override
    public String run(byte[] input) {
        return sign(input);
    }

    private String sign(byte[] input) {
        byte[] signature = mac.doFinal(input);
        return encode(signature);
    }

    private String encode(String input) {
        return encode(input.getBytes(Charset.forName("UTF-8")));
    }

    private String encode(byte[] input) {
        return encoder.encodeToString(input);
    }
}
