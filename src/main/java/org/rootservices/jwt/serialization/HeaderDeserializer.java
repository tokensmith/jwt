package org.rootservices.jwt.serialization;

import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.exception.InvalidJWT;
import org.rootservices.jwt.serialization.exception.JsonException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import java.util.Base64;

public class HeaderDeserializer {
    public static final String JWT_SPLITTER = "\\.";
    public final int JWT_LENGTH = 2;
    public static final String INVALID_HEADER = "JOSE Header is invalid";
    public static final String JWT_IS_NOT_SPLITTABLE = "JWT is not splittable by '.'";
    private Base64.Decoder decoder;
    private Serdes serdes;

    public HeaderDeserializer(Base64.Decoder decoder, Serdes serdes) {
        this.decoder = decoder;
        this.serdes = serdes;
    }

    public Header toHeader(String encodedJwt) throws JsonToJwtException, InvalidJWT {
        String[] jwtParts = encodedJwt.split(JWT_SPLITTER);

        if (jwtParts.length < JWT_LENGTH) {
            throw new InvalidJWT(JWT_IS_NOT_SPLITTABLE);
        }

        byte[] headerJson = decoder.decode(jwtParts[0]);

        Header header;
        try {
            header = (Header) serdes.jsonBytesToObject(headerJson, Header.class);
        } catch (JsonException e) {
            throw new JsonToJwtException(INVALID_HEADER, e);
        }

        return header;
    }

}
