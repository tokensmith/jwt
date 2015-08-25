package org.rootservices.jwt.entity.jwk;

/**
 * Created by tommackenzie on 8/19/15.
 */
public enum KeyType {
    OCT ("oct");

    private String value;

    private KeyType(String value) {
        this.value = value;
    }


    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
