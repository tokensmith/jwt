package org.rootservices.jwt.translator.exception;

/**
 * Created by tommackenzie on 12/8/15.
 */
public class InvalidCsrException extends Exception {
    public InvalidCsrException(String message) {
        super(message);
    }

    public InvalidCsrException(String message, Throwable cause) {
        super(message, cause);
    }
}
