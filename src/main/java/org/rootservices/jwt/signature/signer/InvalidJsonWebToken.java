package org.rootservices.jwt.signature.signer;

/**
 * Created by tommackenzie on 12/7/15.
 */
public class InvalidJsonWebToken extends Exception {
    public InvalidJsonWebToken(String message, Throwable cause) {
        super(message, cause);
    }
}
