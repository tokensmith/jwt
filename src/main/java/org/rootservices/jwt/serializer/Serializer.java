package org.rootservices.jwt.serializer;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.rootservices.jwt.entity.Token;
import org.rootservices.jwt.entity.header.Header;

/**
 * Created by tommackenzie on 8/12/15.
 */
public interface Serializer {
    String objectToJson(Object object) throws JsonProcessingException;
    Object jsonBytesToObject(byte[] json, Class c);
}
