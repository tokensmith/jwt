package org.rootservices.jwt.entity.jwt.header;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by tommackenzie on 8/9/15.
 *
 * JSON Object Signing and Encryption
 */
public class Header {
    @JsonProperty(value="typ")
    TokenType type;
    @JsonProperty(value="alg")
    Algorithm algorithm;

    public TokenType getType() {
        return type;
    }

    public void setType(TokenType type) {
        this.type = type;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

}
