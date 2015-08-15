package org.rootservices.jwt.entity.header;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by tommackenzie on 8/9/15.
 *
 * JSON Object Signing and Encryption
 */
public class Header {
    @JsonProperty(value="alg")
    Algorithm algorithm;

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }
}
