package org.rootservices.jwt.serialization;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;
import org.rootservices.jwt.serialization.exception.JsonException;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

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
public class JWTDeserializer {
    public static final String JWT_SPLITTER = "\\.";
    public final int JWT_LENGTH = 2;
    public final int JWS_LENGTH = 3;
    public final int JWE_LENGTH = 5;
    private Serializer serializer;
    private Encoder encoder;
    private Decoder decoder;
    private final String DELIMITTER = ".";

    public JWTDeserializer(Serializer serializer, Encoder encoder, Decoder decoder) {
        this.serializer = serializer;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    public String makeSignInput(Header header, Claims claims) throws JwtToJsonException {

        String headerJson;
        String claimsJson;

        try {
            headerJson = serializer.objectToJson(header);
            claimsJson = serializer.objectToJson(claims);
        } catch (JsonException e) {
            throw new JwtToJsonException("Could not make sign input", e);
        }

        return encode(headerJson) + DELIMITTER + encode(claimsJson);
    }

    public String jwtToString(JsonWebToken jwt) throws JwtToJsonException {

        StringBuilder encodedJwt = new StringBuilder();
        encodedJwt.append(makeSignInput(jwt.getHeader(), jwt.getClaims()) + DELIMITTER);

        if (jwt.getSignature().isPresent())
            encodedJwt.append(jwt.getSignature().get());

        return encodedJwt.toString();
    }

    private String encode(String input) {
        return encoder.encodeToString(input.getBytes(Charset.forName("UTF-8")));
    }

    public JsonWebToken stringToJwt(String jwtAsText, Class claimClass) throws JsonToJwtException {
        String[] jwtParts = jwtAsText.split(JWT_SPLITTER);
        JsonWebToken jwt = null;

        if (jwtParts.length == JWT_LENGTH) {
            jwt = jwt(jwtParts, claimClass, jwtAsText);
        } else if (jwtParts.length == JWS_LENGTH && jwtParts[JWS_LENGTH-1] != null) {
            jwt = jws(jwtParts, claimClass, jwtAsText);
        } else if (jwtParts.length == JWE_LENGTH) {
            // TODO: throw a exception here.
        } else {
            // TODO: throw a exception here.
        }

        return jwt;
    }

    protected JsonWebToken jwt(String[] jwtParts, Class claimClass, String jwtAsText) throws JsonToJwtException {
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

        return jwt;
    }

    protected JsonWebToken jws(String[] jwsParts, Class claimClass, String jwtAsText) throws JsonToJwtException {
        JsonWebToken jwt = jwt(jwsParts, claimClass, jwtAsText);
        jwt.setSignature(Optional.of(jwsParts[JWS_LENGTH-1]));

        return jwt;
    }

}
