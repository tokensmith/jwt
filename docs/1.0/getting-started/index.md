---
layout: default
title: Getting started
categories: [1.0]
---

### {{ page.title }} ###

A basic understanding of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) (JWT) 
and [JSON Web Signatures](https://tools.ietf.org/html/rfc7515) (JWS) is recommended.

##### Maven dependency #####

{% highlight xml %}
<dependency>
    <groupId>org.rootservices</groupId>
    <artifactId>jwt</artifactId>
    <version>{{ site.latest_release }}</version>
</dependency>
{% endhighlight %}

##### Extend the Claim class to add claims #####

{% highlight java %}
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
        return someAdditionalClaim;
    }

    public void setSomeAdditionalClaim(Boolean someAdditionalClaim) {
        this.someAdditionalClaim = someAdditionalClaim;
    }
}
{% endhighlight %}

##### Unsecured JWT example #####

{% highlight java %}
AppFactory appFactory = new AppFactory();
UnsecureTokenBuilder unsecureTokenBuilder = appFactory.unsecureTokenBuilder();

Claim claim = new Claim();
claim.setSomeAdditionalClaim(true);

Token token = unsecureTokenBuilder.build(claim);

JWTSerializer jwtSerializer = appFactory.jwtSerializer();
String jwt = jwtSerializer.tokenToJwt(token);
{% endhighlight %}


##### Secured JWT with HS256 symmetric key example #####

{% highlight java %}
Key key = new Key();
key.setKeyType(KeyType.OCT);
key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

AppFactory appFactory = new AppFactory();
SecureTokenBuilder secureTokenBuilder = appFactory.secureTokenBuilder(Algorithm.HS256, key);

Claim claim = new Claim();
claim.setSomeAdditionalClaim(true);

Token token = secureTokenBuilder.build(Algorithm.HS256, claim);

JWTSerializer jwtSerializer = appFactory.jwtSerializer();
String jwt = jwtSerializer.tokenToJwt(token);
{% endhighlight %}

The example above is documented in [JWS](https://tools.ietf.org/html/rfc7515#appendix-A.1)

- `key` represents a [JSON Web Kek](https://tools.ietf.org/html/rfc7517) (JWK) 
- `KeyType.OCT` indicates it's a symmetric key, documented in [JSON Web Algorithms](https://tools.ietf.org/html/rfc7518#section-6.1) (JWA).
- The key value, `AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow` is the base64 encoded value of the key value. The key value is an octect sequence. Which is documented in [JWA](https://tools.ietf.org/html/rfc7518#section-6.4.1)

##### JWT to an instance of a Token - verify signature #####

{% highlight java %}
AppFactory appFactory = new AppFactory();

JWTSerializer jwtSerializer = appFactory.jwtSerializer();
Token token = jwtSerializer.jwtToToken(jwt, Claim.class);

Key key = new Key();
key.setKeyType(KeyType.OCT);
key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

VerifySignature verifySignature = appFactory.verifySignature();
boolean isVerified = verifySignature.run(token, key);
{% endhighlight %}