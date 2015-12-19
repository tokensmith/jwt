package org.rootservices.jwt.serializer.exception;

/**
 * Created by tommackenzie on 12/5/15.
 *
 * Thrown when a JSON string could be serialized to a JsonWebToken object.
 */
public class JsonToJwtException extends Exception {
    public JsonToJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
