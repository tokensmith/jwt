package net.tokensmith.jwt.jws.signer;

import net.tokensmith.jwt.entity.jwt.header.Algorithm;

/**
 * Created by tommackenzie on 8/22/15.
 */
public enum SignAlgorithm {
    HS256 (Algorithm.HS256, "HmacSHA256"),
    RS256 (Algorithm.RS256, "SHA256withRSA");

    private Algorithm jwtAglgorithm;
    private String jdkAlgorithm;

    SignAlgorithm(Algorithm jwtAglgorithm, String jdkAlgorithm) {
        this.jwtAglgorithm = jwtAglgorithm;
        this.jdkAlgorithm = jdkAlgorithm;
    }

    public Algorithm getJwtAglgorithm() {
        return jwtAglgorithm;
    }

    public void setJwtAglgorithm(Algorithm jwtAglgorithm) {
        this.jwtAglgorithm = jwtAglgorithm;
    }

    public String getJdkAlgorithm() {
        return jdkAlgorithm;
    }

    public void setJdkAlgorithm(String jdkAlgorithm) {
        this.jdkAlgorithm = jdkAlgorithm;
    }
}
