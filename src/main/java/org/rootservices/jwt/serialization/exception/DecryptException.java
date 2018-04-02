package org.rootservices.jwt.serialization.exception;

public class DecryptException extends Exception {
    public DecryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
