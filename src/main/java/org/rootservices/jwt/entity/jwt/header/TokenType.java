package org.rootservices.jwt.entity.jwt.header;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Created by tommackenzie on 8/23/15.
 */
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum TokenType {
    JWT ("JWT");

    private String value;

    TokenType(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
