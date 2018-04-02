package org.rootservices.jwt.serialization.exception;

/**
 * Created by tommackenzie on 12/12/15.
 *
 * Is thrown when a JsonWebToken can not be serialized to JSON
 */
public class JwtToJsonException extends Exception {
    public JwtToJsonException(String message, Throwable cause) {
        super(message, cause);
    }
}
