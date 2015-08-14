package org.rootservices.jwt.serializer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.rootservices.jwt.entity.header.Header;
import org.rootservices.jwt.serializer.Serializer;

import java.io.IOException;

/**
 * Created by tommackenzie on 8/12/15.
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
    public Object bytesToObject(byte[] json, Class c) {
        Object object = null;
        try {
            object = objectMapper.readValue(json, c);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return object;
    }
}
