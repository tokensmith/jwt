package org.rootservices.jwt.jws.signer.factory.rsa.exception;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class SignatureException extends Exception {
    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
