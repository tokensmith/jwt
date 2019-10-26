package net.tokensmith.jwt.jws.signer.factory.hmac.exception;

/**
 * Created by tommackenzie on 12/13/15.
 *
 * Used when an issue occurs initializing a mac with a security key.
 */
public class SecurityKeyException extends Exception {
    public SecurityKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
