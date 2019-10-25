package net.tokensmith.jwt.jwe;

public enum Transformation {
    // RSA_OAEP ("RSA/ECB/OAEPWithSHA-1AndMGF1Padding"),
    RSA_OAEP ("RSA/ECB/OAEPPadding"),
    AES_GCM_NO_PADDING ("AES/GCM/NoPadding");

    private String value;

    Transformation(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
