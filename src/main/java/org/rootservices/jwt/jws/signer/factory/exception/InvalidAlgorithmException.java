package org.rootservices.jwt.jws.signer.factory.exception;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class InvalidAlgorithmException extends Exception {
    public InvalidAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }
}
