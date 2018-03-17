package org.rootservices.jwt.entity.jwe;

import com.fasterxml.jackson.annotation.JsonValue;

public enum EncryptionAlgorithm {
    AES_GCM_256 ("A256GCM");

    private String value;

    EncryptionAlgorithm(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
