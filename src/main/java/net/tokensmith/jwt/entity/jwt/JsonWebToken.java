package net.tokensmith.jwt.entity.jwt;


import net.tokensmith.jwt.entity.jwt.header.Header;

import java.util.Optional;

/**
 * Created by tommackenzie on 8/9/15.
 */
public class JsonWebToken {
    private Header header;
    private Claims claims;
    private Optional<byte[]> signature = Optional.empty();
    private Optional<String> jwt = Optional.empty();

    public JsonWebToken() {}

    public JsonWebToken(Header header, Claims claims) {
        this.header = header;
        this.claims = claims;
    }

    public JsonWebToken(Header header, Claims claims, Optional<String> jwt) {
        this.header = header;
        this.claims = claims;
        this.jwt = jwt;
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public Claims getClaims() {
        return claims;
    }

    public void setClaims(Claims claims) {
        this.claims = claims;
    }

    public Optional<byte[]> getSignature() {
        return signature;
    }

    public void setSignature(Optional<byte[]> signature) {
        this.signature = signature;
    }

    public Optional<String> getJwt() {
        return jwt;
    }

    public void setJwt(Optional<String> jwt) {
        this.jwt = jwt;
    }
}
