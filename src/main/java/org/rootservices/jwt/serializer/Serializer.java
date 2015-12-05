package org.rootservices.jwt.serializer;

import org.rootservices.jwt.serializer.exception.JsonException;

/**
 * Created by tommackenzie on 8/12/15.
 */
public interface Serializer {
    String objectToJson(Object object) throws JsonException;
    Object jsonBytesToObject(byte[] json, Class<?> c) throws JsonException;
}
