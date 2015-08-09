package main.java.org.rootservices.jwt.entity;

import main.java.org.rootservices.jwt.entity.jose.header;

import java.util.Optional;

/**
 * Created by tommackenzie on 8/9/15.
 */
public class JSONWebToken {
    private header JOSEHeader;
    private RegisteredClaimNames registeredClaimNames;
    private Optional<String> JWSSignature;

    public header getJOSEHeader() {
        return JOSEHeader;
    }

    public void setJOSEHeader(header JOSEHeader) {
        this.JOSEHeader = JOSEHeader;
    }

    public RegisteredClaimNames getRegisteredClaimNames() {
        return registeredClaimNames;
    }

    public void setRegisteredClaimNames(RegisteredClaimNames registeredClaimNames) {
        this.registeredClaimNames = registeredClaimNames;
    }

    public Optional<String> getJWSSignature() {
        return JWSSignature;
    }

    public void setJWSSignature(Optional<String> JWSSignature) {
        this.JWSSignature = JWSSignature;
    }
}
