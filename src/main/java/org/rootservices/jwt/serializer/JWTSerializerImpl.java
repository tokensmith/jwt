package org.rootservices.jwt.serializer;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.rootservices.jwt.entity.jwt.RegisteredClaimNames;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Header;

import java.nio.charset.Charset;

import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

/**
 * Created by tommackenzie on 8/13/15.
 *
 * A Serializer that converts:
 * - a jwt string to a intance of a Token.
 * - a token to its jwt string.
 */
public class JWTSerializerImpl implements JWTSerializer {
    private Serializer serializer;
    private Encoder encoder;
    private Decoder decoder;

    public JWTSerializerImpl(Serializer serializer, Encoder encoder, Decoder decoder) {
        this.serializer = serializer;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    @Override
    public String tokenToJwt(Token token) {
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

        // TODO: add signature

        return jwt;
    }

    @Override
    public Token jwtToToken(String jwt, Class claimClass) {
        String[] jwtParts = jwt.split("\\.");

        byte[] headerJson = decoder.decode(jwtParts[0]);
        byte[] claimsJson = decoder.decode(jwtParts[1]);

        Header header = (Header) serializer.jsonBytesToObject(headerJson, Header.class);
        RegisteredClaimNames claim = (RegisteredClaimNames) serializer.jsonBytesToObject(claimsJson, claimClass);

        Token token = new Token();
        token.setHeader(header);
        token.setClaimNames(claim);

        // TODO: add signature.. should it verify the token? no

        return token;
    }
}
