package net.tokensmith.jwt.jwe.entity;

import net.tokensmith.jwt.entity.jwt.header.Header;

public class JWE {
    private Header header;
    private byte[] payload;
    private byte[] cek;
    private byte[] iv;
    private byte[] authTag;

    public JWE() {}

    public JWE(Header header, byte[] payload, byte[] cek, byte[] iv, byte[] authTag) {
        this.header = header;
        this.payload = payload;
        this.cek = cek;
        this.iv = iv;
        this.authTag = authTag;
    }

    public Header getHeader() {
        return header;
    }

    public void setHeader(Header header) {
        this.header = header;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    public byte[] getCek() {
        return cek;
    }

    public void setCek(byte[] cek) {
        this.cek = cek;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getAuthTag() {
        return authTag;
    }

    public void setAuthTag(byte[] authTag) {
        this.authTag = authTag;
    }
}
