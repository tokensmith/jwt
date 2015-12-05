package org.rootservices.jwt.serializer.exception;

/**
 * Created by tommackenzie on 12/5/15.
 */
public class InvalidJwtException extends Exception {
    public InvalidJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
