package net.tokensmith.jwt.serialization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.tokensmith.jwt.serialization.exception.JsonException;

import java.io.IOException;

/**
 * A Generic serializer and deserializer that converts:
 * - an object to json
 * - json to a object
 *
 */
public class Serdes {
    public static final String COULD_NOT_CREATE_JSON_FROM = "Could not create json from %s";
    private ObjectMapper objectMapper;

    public Serdes(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public byte[] objectToByte(Object object) throws JsonException {
        try {
            return objectMapper.writeValueAsBytes(object);
        } catch (JsonProcessingException e) {
            throw new JsonException(String.format(COULD_NOT_CREATE_JSON_FROM ,object.toString()), e);
        }
    }

    public Object jsonBytesToObject(byte[] json, Class<?> c) throws JsonException {
        Object object;
        try {
            object = objectMapper.readValue(json, c);
        } catch (IOException e) {
            throw new JsonException("Could not create " + c.toString() +" from json byes, " + json.toString(), e);
        }
        return object;
    }
}
