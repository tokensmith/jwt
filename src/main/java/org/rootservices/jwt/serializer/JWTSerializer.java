package org.rootservices.jwt.serializer;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.serializer.exception.JsonToJwtException;
import org.rootservices.jwt.serializer.exception.JsonException;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;

import java.nio.charset.Charset;

import java.util.Base64.Encoder;
import java.util.Base64.Decoder;
import java.util.Optional;

/**
 * Created by tommackenzie on 8/13/15.
 *
 * A Serializer that converts:
 * - a jwt as a string to a instance of a JsonWebToken.
 * - a JsonWebToken to its string representation.
 */
public class JWTSerializer {
    private final int SECURE_TOKEN_LENGTH = 3;
    private Serializer serializer;
    private Encoder encoder;
    private Decoder decoder;
    private final String DELIMITTER = ".";

    public JWTSerializer(Serializer serializer, Encoder encoder, Decoder decoder) {
        this.serializer = serializer;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    public String makeSignInput(Header header, Claims claims) throws JwtToJsonException {

        String headerJson = "";
        String claimsJson = "";

        try {
            headerJson = serializer.objectToJson(header);
            claimsJson = serializer.objectToJson(claims);
        } catch (JsonException e) {
            throw new JwtToJsonException("Could not make sign input", e);
        }

        return encode(headerJson) + DELIMITTER + encode(claimsJson);
    }

    public String jwtToString(JsonWebToken jwt) throws JwtToJsonException {

        String jwtAsText = makeSignInput(jwt.getHeader(), jwt.getClaims()) + DELIMITTER;

        if (jwt.getSignature().isPresent())
            jwtAsText+= jwt.getSignature().get();

        return jwtAsText;
    }

    private String encode(String input) {
        return encoder.encodeToString(input.getBytes(Charset.forName("UTF-8")));
    }

    public JsonWebToken stringToJwt(String jwtAsText, Class claimClass) throws JsonToJwtException {
        String[] jwtParts = jwtAsText.split("\\.");

        byte[] headerJson = decoder.decode(jwtParts[0]);
        byte[] claimsJson = decoder.decode(jwtParts[1]);

        Header header;
        Claims claim;
        try {
            header = (Header) serializer.jsonBytesToObject(headerJson, Header.class);
            claim = (Claims) serializer.jsonBytesToObject(claimsJson, claimClass);
        } catch (JsonException e) {
            throw new JsonToJwtException("JWT json is invalid", e);
        }

        JsonWebToken jwt = new JsonWebToken(header, claim, Optional.of(jwtAsText));

        if (jwtParts.length == SECURE_TOKEN_LENGTH && jwtParts[SECURE_TOKEN_LENGTH-1] != null)
            jwt.setSignature(Optional.of(jwtParts[SECURE_TOKEN_LENGTH-1]));

        return jwt;
    }
}
