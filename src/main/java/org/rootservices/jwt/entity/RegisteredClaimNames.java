package org.rootservices.jwt.entity;

import java.util.List;
import java.util.Optional;

/**
 * Created by tommackenzie on 8/9/15.
 *
 * https://tools.ietf.org/html/rfc7519#section-4.1
 */
public class RegisteredClaimNames {

    private Optional<String> issuer;
    private Optional<String> subject;
    private List<String> audience;
    private Optional<String> expirationTime;
    private Optional<Long> notBefore;
    private Optional<Long> issuedAt;
    private Optional<String> jwtId;

    public Optional<String> getIssuer() {
        return issuer;
    }

    public void setIssuer(Optional<String> issuer) {
        this.issuer = issuer;
    }

    public Optional<String> getSubject() {
        return subject;
    }

    public void setSubject(Optional<String> subject) {
        this.subject = subject;
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public Optional<String> getExpirationTime() {
        return expirationTime;
    }

    public void setExpirationTime(Optional<String> expirationTime) {
        this.expirationTime = expirationTime;
    }

    public Optional<Long> getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Optional<Long> notBefore) {
        this.notBefore = notBefore;
    }

    public Optional<Long> getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Optional<Long> issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Optional<String> getJwtId() {
        return jwtId;
    }

    public void setJwtId(Optional<String> jwtId) {
        this.jwtId = jwtId;
    }
}
