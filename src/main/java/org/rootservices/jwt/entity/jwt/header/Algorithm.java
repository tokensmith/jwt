package org.rootservices.jwt.entity.jwt.header;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Created by tommackenzie on 8/9/15.
 */
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum Algorithm {
    NONE ("none", AlgorithmFor.JWS),
    HS256 ("HS256", AlgorithmFor.JWS),
    RS256 ("RS256", AlgorithmFor.JWS),
    RSAES_OAEP  ("RSA-OAEP", AlgorithmFor.JWE);

    private String value;
    private AlgorithmFor algorithmFor;

    Algorithm(String value, AlgorithmFor algorithmFor) {
        this.value = value;
        this.algorithmFor = algorithmFor;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public AlgorithmFor getAlgorithmFor() {
        return algorithmFor;
    }
}
