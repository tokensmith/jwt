package org.rootservices.jwt.signature.signer.factory.exception;

/**
 * Created by tommackenzie on 12/13/15.
 */
public class InvalidJsonWebTokenException extends Exception {
    public InvalidJsonWebTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
