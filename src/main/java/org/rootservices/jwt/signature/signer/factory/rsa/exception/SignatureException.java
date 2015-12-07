package org.rootservices.jwt.signature.signer.factory.rsa.exception;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class SignatureException extends Exception {
    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
