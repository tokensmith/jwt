package org.rootservices.jwt.marshaller;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.rootservices.jwt.entity.RegisteredClaimNames;
import org.rootservices.jwt.entity.Token;
import org.rootservices.jwt.entity.header.Header;
import org.rootservices.jwt.serializer.Serializer;

import java.nio.charset.Charset;

import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

/**
 * Created by tommackenzie on 8/13/15.
 */
public class TokenMarshallerImpl implements TokenMarshaller {
    private Serializer serializer;
    private Encoder encoder;
    private Decoder decoder;

    public TokenMarshallerImpl(Serializer serializer, Encoder encoder, Decoder decoder) {
        this.serializer = serializer;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    @Override
    public String tokenToString(Token token) {
        String jwt = "";
        String headerJson = "";
        String claimsJson = "";

        try {
            headerJson = serializer.objectToJson(token.getHeader());
            claimsJson = serializer.objectToJson(token.getClaimNames());
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        jwt = encoder.encodeToString(headerJson.getBytes(Charset.forName("UTF-8"))) +
                "." +
                encoder.encodeToString(claimsJson.getBytes(Charset.forName("UTF-8"))) +
                ".";

        return jwt;
    }

    @Override
    public Token stringToToken(String jwt, Class claimClass) {
        String[] jwtParts = jwt.split("\\.");

        byte[] headerJson = decoder.decode(jwtParts[0]);
        byte[] claimsJson = decoder.decode(jwtParts[1]);

        Header header = (Header) serializer.bytesToObject(headerJson, Header.class);
        RegisteredClaimNames claim = (RegisteredClaimNames) serializer.bytesToObject(claimsJson, claimClass);

        Token token = new Token();
        token.setHeader(header);
        token.setClaimNames(claim);

        return token;
    }
}
