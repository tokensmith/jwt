package org.rootservices.jwt.translator.exception;

/**
 * Created by tommackenzie on 12/8/15.
 */
public class InvalidPemException extends Exception {
    public InvalidPemException(String message) {
        super(message);
    }

    public InvalidPemException(String message, Throwable cause) {
        super(message, cause);
    }
}
