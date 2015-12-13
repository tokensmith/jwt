package org.rootservices.jwt.exception;

/**
 * Created by tommackenzie on 12/8/15.
 */
public class InvalidKeyException extends Exception {
    public InvalidKeyException(String message) {
        super(message);
    }

    public InvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
