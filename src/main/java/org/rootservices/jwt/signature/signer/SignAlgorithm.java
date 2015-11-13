package org.rootservices.jwt.signature.signer;

/**
 * Created by tommackenzie on 8/22/15.
 *
 * Algorithms used for JSON Web Signature
 */
public enum SignAlgorithm {
    HS256 ("HmacSHA256"),
    RS256 ("SHA256withRSA");

    private String value;

    SignAlgorithm(String value) {
        this.value = value;
    }


    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
