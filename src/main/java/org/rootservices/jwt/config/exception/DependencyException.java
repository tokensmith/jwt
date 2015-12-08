package org.rootservices.jwt.config.exception;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class DependencyException extends Exception {
    public DependencyException(String message, Throwable cause) {
        super(message, cause);
    }
}
