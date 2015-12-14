package org.rootservices.jwt.signature.signer.factory.exception;

/**
 * Created by tommackenzie on 12/13/15.
 */
public class InvalidJsonWebKeyException extends Exception {
    public InvalidJsonWebKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
