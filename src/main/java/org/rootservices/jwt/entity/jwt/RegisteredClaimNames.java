package org.rootservices.jwt.entity.jwt;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Optional;

/**
 * Created by tommackenzie on 8/9/15.
 *
 * https://tools.ietf.org/html/rfc7519#section-4.1
 */
public class RegisteredClaimNames {
    @JsonProperty(value="iss")
    private Optional<String> issuer = Optional.empty();
    @JsonProperty(value="sub")
    private Optional<String> subject = Optional.empty();
    @JsonProperty(value="aud")
    private List<String> audience;
    @JsonProperty(value="exp")
    private Optional<Long> expirationTime = Optional.empty();
    @JsonProperty(value="nbf")
    private Optional<Long> notBefore = Optional.empty();
    @JsonProperty(value="iat")
    private Optional<Long> issuedAt = Optional.empty();
    @JsonProperty(value="jti")
    private Optional<String> jwtId = Optional.empty();

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

    public Optional<Long> getExpirationTime() {
        return expirationTime;
    }

    public void setExpirationTime(Optional<Long> expirationTime) {
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
