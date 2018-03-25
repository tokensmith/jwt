package org.rootservices.jwt.serializer.exception;

public class DecryptException extends Exception {
    public DecryptException(String message, Throwable cause) {
        super(message, cause);
    }
}
