package org.rootservices.jwt.serializer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

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
    public String objectToJson(Object object) throws JsonProcessingException {
        return objectMapper.writeValueAsString(object);
    }

    @Override
    public Object jsonBytesToObject(byte[] json, Class c) {
        Object object = null;
        try {
            object = objectMapper.readValue(json, c);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return object;
    }
}
