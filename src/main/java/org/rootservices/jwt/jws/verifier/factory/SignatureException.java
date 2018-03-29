package org.rootservices.jwt.jws.verifier.factory;

/**
 * Represents when a Signer could not be constructed due to a invalid key or algorithm.
 */
public class SignatureException extends Exception {
    public SignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
