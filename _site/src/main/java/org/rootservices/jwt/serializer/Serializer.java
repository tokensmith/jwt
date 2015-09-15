package org.rootservices.jwt.serializer;

import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Created by tommackenzie on 8/12/15.
 */
public interface Serializer {
    String objectToJson(Object object) throws JsonProcessingException;
    Object jsonBytesToObject(byte[] json, Class c);
}
