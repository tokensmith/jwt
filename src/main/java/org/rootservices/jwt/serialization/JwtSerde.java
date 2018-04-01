package org.rootservices.jwt.serialization;

import org.rootservices.jwt.entity.jwt.Claims;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.exception.InvalidJWT;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;
import org.rootservices.jwt.serialization.exception.JsonException;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.ArrayList;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Optional;


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
    public static final String COULD_NOT_COMBINE_JWT_MEMBERS = "Could not combine jwt members";
    public static final String COULD_NOT_COMBINE_SIGN_INPUTS = "Could not combine sign inputs";
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

        List<byte[]> members = membersForSigning(header, claims);
        byte[] signInput;

        try {
            signInput = compact(members, true).toByteArray();
        } catch (IOException e) {
            throw  new JwtToJsonException(COULD_NOT_COMBINE_SIGN_INPUTS, e);
        }

        return signInput;
    }

    protected List<byte[]> membersForSigning(Header header, Claims claims) throws JwtToJsonException {
        List<byte[]> members = new ArrayList<>();
        byte[] headerJson;
        byte[] claimsJson;

        try {
            headerJson = serdes.objectToByte(header);
            claimsJson = serdes.objectToByte(claims);
        } catch (JsonException e) {
            throw new JwtToJsonException(COULD_NOT_SERIALIZE, e);
        }

        members.add(encoder.encode(headerJson));
        members.add(encoder.encode(claimsJson));
        return members;
    }

    public ByteArrayOutputStream compactJwt(JsonWebToken jwt) throws JwtToJsonException {

        List<byte[]> members = membersForSigning(jwt.getHeader(), jwt.getClaims());

        if (jwt.getSignature().isPresent())
            members.add(jwt.getSignature().get());

        ByteArrayOutputStream compactJwt;
        try {
            compactJwt = compact(members, false);
        } catch (IOException e) {
            throw new JwtToJsonException(COULD_NOT_COMBINE_JWT_MEMBERS, e);
        }
        return compactJwt;
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

    protected ByteArrayOutputStream compact(List<byte[]> members, Boolean forSigning) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        for(int i=0; i < members.size(); i++) {
            if (members.get(i) != null) {
                try {
                    outputStream.write(members.get(i));
                } catch (IOException e) {
                    throw e;
                }
            }
            if (shouldAppendDelimiter(i, members.size(), forSigning)) {
                try {
                    outputStream.write(DELIMITER);
                } catch (IOException e) {
                    throw e;
                }
            }
        }
        return outputStream;
    }

    /**
     * Deteremines if a "." should be appended to the current index of a compact jwt.
     *
     * When its not for signing
     *
     * Then a un secure jwt will have a trailing "."
     * Then a secure jwt (signed) will not have a trailing "."
     *
     * When its for signing
     * Then a un secure jwt will have a trailing "."
     *
     * @param i the current index of the jwt
     * @param numberOfMembers the number of members in the jwt
     * @param forSigning is it being compacted to be signed.
     * @return true if a "." should be appended. false if not.
     */
    protected Boolean shouldAppendDelimiter(int i, int numberOfMembers, Boolean forSigning) {
        return (i < numberOfMembers - 1 || (forSigning == false && i == numberOfMembers - 1 && i == 1));
    }

}
