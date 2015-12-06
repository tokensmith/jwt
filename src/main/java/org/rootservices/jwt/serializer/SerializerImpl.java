package org.rootservices.jwt.serializer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.rootservices.jwt.serializer.exception.JsonException;

import java.io.IOException;

/**
 * Created by tommackenzie on 8/12/15.
 *
 * A Generic serializer that converts:
 * - a object to json
 * - json to a object
 *
 */
public class SerializerImpl implements Serializer {

    private ObjectMapper objectMapper;

    public SerializerImpl(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String objectToJson(Object object) throws JsonException {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            throw new JsonException("Could not create json from " + object.toString(), e);
        }
    }

    @Override
    public Object jsonBytesToObject(byte[] json, Class<?> c) throws JsonException {
        Object object = null;
        try {
            object = objectMapper.readValue(json, c);
        } catch (IOException e) {
            throw new JsonException("Could not create " + c.toString() +" from json byes, " + json.toString(), e);
        }
        return object;
    }
}
