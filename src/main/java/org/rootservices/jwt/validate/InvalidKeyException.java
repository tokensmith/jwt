package org.rootservices.jwt.validate;

/**
 * Created by tommackenzie on 12/6/15.
 */
public class InvalidKeyException extends Exception {
    public InvalidKeyException(String message) {
        super(message);
    }
}
