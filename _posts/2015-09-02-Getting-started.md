---
layout: default
title: Getting started
---

### {{ page.title }} ###

*Maven dependency*

~~~
<dependency>
    <groupId>org.rootservices</groupId>
    <artifactId>jwt</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
~~~

*Extend the Claim class to add claims*

~~~
package com.organization.project;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.rootservices.jwt.entity.jwt.Claims;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class Claim extends Claims {

    @JsonProperty(value="additionalClaim")
    private Boolean someAdditionalClaim;

    public Boolean getSomeAdditionalClaim() {
        return uriIsRoot;
    }

    public void setSomeAdditionalClaim(Boolean someAdditionalClaim) {
        this.someAdditionalClaim = someAdditionalClaim;
    }
}
~~~

*Unsecured JWT example*

~~~
Key key = new Key();
key.setKeyType(KeyType.OCT);
key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

AppFactory appFactory = new AppFactory();
TokenBuilder tokenBuilder = appFactory.tokenBuilder(Algorithm.HS256, key);

Claim claim = new Claim();
claim.setSomeAdditionalClaim(true);

Token token = tokenBuilder.makeUnsecuredToken(claim);

JwtSerializer jwtSerializer = appFactory.jwtSerializer();
String jwt = jwtSerializer.tokenToJwt(token);
~~~


*Secured JWT with HS256 symmetric key example*

~~~
Key key = new Key();
key.setKeyType(KeyType.OCT);
key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

AppFactory appFactory = new AppFactory();
TokenBuilder tokenBuilder = appFactory.tokenBuilder(Algorithm.HS256, key);

Claim claim = new Claim();
claim.setSomeAdditionalClaim(true);

Token token = tokenBuilder.makeSignedToken(Algorithm.HS256, claim);

JwtSerializer jwtSerializer = appFactory.jwtSerializer();
String jwt = jwtSerializer.tokenToJwt(token);
~~~

*JWT to an instance of a Token - verify signature*

~~~
Key key = new Key();
key.setKeyType(KeyType.OCT);
key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

JwtSerializer jwtSerializer = appFactory.jwtSerializer();
Token token = jwtSerializer.jwtToToken(jwt, Claim.class);

VerifySignature verifySignature = appFactory.verifySignature();
boolean isVerified = verifySignature.run(token, key);
~~~
