package org.rootservices.jwt.entity.header;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Created by tommackenzie on 8/9/15.
 */
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum Algorithm {
    NONE ("none");

    private String value;

    private Algorithm(String value) {
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
