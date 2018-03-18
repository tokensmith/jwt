package org.rootservices.jwt.serializer;

import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.exception.InvalidJWT;
import org.rootservices.jwt.serializer.exception.JsonException;
import org.rootservices.jwt.serializer.exception.JsonToJwtException;

import java.util.Base64;

public class HeaderSerializer {
    public static final String JWT_SPLITTER = "\\.";
    public static final String INVALID_HEADER = "JOSE Header is invalid";
    public static final String JWT_IS_NOT_SPLITTABLE = "JWT is not splittable by '.'";
    private Base64.Decoder decoder;
    private Serializer serializer;

    public HeaderSerializer(Base64.Decoder decoder, Serializer serializer) {
        this.decoder = decoder;
        this.serializer = serializer;
    }

    public Header toHeader(String encodedJwt) throws JsonToJwtException, InvalidJWT {
        String[] jwtParts = encodedJwt.split(JWT_SPLITTER);

        if (jwtParts.length == 0) {
            throw new InvalidJWT(JWT_IS_NOT_SPLITTABLE);
        }

        byte[] headerJson = decoder.decode(jwtParts[0]);

        Header header;
        try {
            header = (Header) serializer.jsonBytesToObject(headerJson, Header.class);
        } catch (JsonException e) {
            throw new JsonToJwtException(INVALID_HEADER, e);
        }

        return header;
    }

}
