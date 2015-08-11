package org.rootservices.jwt.entity;


import org.rootservices.jwt.entity.header.Header;

import java.util.Optional;

/**
 * Created by tommackenzie on 8/9/15.
 */
public class Token {
    private Header header;
    private RegisteredClaimNames claimNames;
    private Optional<String> signature;

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public RegisteredClaimNames getClaimNames() {
        return claimNames;
    }

    public void setClaimNames(RegisteredClaimNames claimNames) {
        this.claimNames = claimNames;
    }

    public Optional<String> getSignature() {
        return signature;
    }

    public void setSignature(Optional<String> signature) {
        this.signature = signature;
    }
}
