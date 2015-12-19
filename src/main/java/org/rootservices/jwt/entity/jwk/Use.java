package org.rootservices.jwt.entity.jwk;

/**
 * Created by tommackenzie on 11/5/15.
 */
public enum Use {
    SIGNATURE("sig"),
    ENCRYPTION("enc");

    private String value;

    Use(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
