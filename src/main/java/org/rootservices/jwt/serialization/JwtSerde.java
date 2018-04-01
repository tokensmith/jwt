package org.rootservices.jwt.serialization;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.exception.InvalidJWT;
import org.rootservices.jwt.serialization.exception.EncryptException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;
import org.rootservices.jwt.serialization.exception.JsonException;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Optional;

import static org.rootservices.jwt.jwe.serialization.JweSerializer.COULD_NOT_COMPACT;

/**
 * A Serializer and Deserializer that converts:
 * - a jwt as a string to a instance of a JsonWebToken.
 * - a JsonWebToken to its string representation.
 */
public class JwtSerde {
    public static final String JWT_SPLITTER = "\\.";
    public static final String INVALID_JSON = "JWT json is invalid";
    public static final String COULD_NOT_SERIALIZE = "Could not make sign input";
    public static final String THIS_IS_A_JWE = "This is a JWE";
    public static final String TOO_MANY_MEMBERS = "Too many members";
    public final int JWT_LENGTH = 2;
    public final int JWS_LENGTH = 3;
    public final int JWE_LENGTH = 5;
    private Serdes serdes;
    private Encoder encoder;
    private Decoder decoder;
    private final String DELIMITTER = ".";
    private final byte[] DELIMITER = ".".getBytes();

    public JwtSerde(Serdes serdes, Encoder encoder, Decoder decoder) {
        this.serdes = serdes;
        this.encoder = encoder;
        this.decoder = decoder;
    }

    public byte[] makeSignInput(Header header, Claims claims) throws JwtToJsonException {

        byte[] headerJson;
        byte[] claimsJson;

        try {
            headerJson = serdes.objectToByte(header);
            claimsJson = serdes.objectToByte(claims);
        } catch (JsonException e) {
            throw new JwtToJsonException(COULD_NOT_SERIALIZE, e);
        }

        List<byte[]> parts = new ArrayList<>();
        parts.add(encoder.encode(headerJson));
        parts.add(encoder.encode(claimsJson));
        byte[] signInput;

        try {
            signInput = compact(parts);
        } catch (IOException e) {
            throw  new JwtToJsonException("Could not combine sign inputs", e);
        }

        return signInput;
    }

    public String compactJwt(JsonWebToken jwt) throws JwtToJsonException {

        StringBuilder compactJwt = new StringBuilder();
        byte[] signInput = makeSignInput(jwt.getHeader(), jwt.getClaims());

        compactJwt.append(new String(signInput, StandardCharsets.UTF_8));
        compactJwt.append(DELIMITTER);

        if (jwt.getSignature().isPresent())
            compactJwt.append(new String(jwt.getSignature().get(), StandardCharsets.UTF_8));

        return compactJwt.toString();
    }

    public JsonWebToken stringToJwt(String jwtAsText, Class claimClass) throws JsonToJwtException, InvalidJWT {
        String[] jwtParts = jwtAsText.split(JWT_SPLITTER);
        JsonWebToken jwt;

        if (jwtParts.length == JWT_LENGTH) {
            jwt = jwt(jwtParts, claimClass, jwtAsText);
        } else if (jwtParts.length == JWS_LENGTH && jwtParts[JWS_LENGTH-1] != null) {
            jwt = jws(jwtParts, claimClass, jwtAsText);
        } else if (jwtParts.length == JWE_LENGTH) {
            throw new InvalidJWT(THIS_IS_A_JWE);
        } else {
            throw new InvalidJWT(TOO_MANY_MEMBERS);
        }

        return jwt;
    }

    protected JsonWebToken jwt(String[] jwtParts, Class claimClass, String jwtAsText) throws JsonToJwtException {
        byte[] headerJson = decoder.decode(jwtParts[0]);
        byte[] claimsJson = decoder.decode(jwtParts[1]);

        Header header;
        Claims claim;
        try {
            header = (Header) serdes.jsonBytesToObject(headerJson, Header.class);
            claim = (Claims) serdes.jsonBytesToObject(claimsJson, claimClass);
        } catch (JsonException e) {
            throw new JsonToJwtException(INVALID_JSON, e);
        }

        JsonWebToken jwt = new JsonWebToken(header, claim, Optional.of(jwtAsText));

        return jwt;
    }

    protected JsonWebToken jws(String[] jwsParts, Class claimClass, String jwtAsText) throws JsonToJwtException {
        JsonWebToken jwt = jwt(jwsParts, claimClass, jwtAsText);
        jwt.setSignature(Optional.of(jwsParts[JWS_LENGTH-1].getBytes()));

        return jwt;
    }

    protected byte[] compact(List<byte[]> parts) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        for(int i=0; i < parts.size(); i++) {
            if (parts.get(i) != null) {
                try {
                    outputStream.write(parts.get(i));
                } catch (IOException e) {
                    throw e;
                }
            }
            if (i < parts.size() - 1) {
                try {
                    outputStream.write(DELIMITER);
                } catch (IOException e) {
                    throw e;
                }
            }
        }
        return outputStream.toByteArray();
    }

}
