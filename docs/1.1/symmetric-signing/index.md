---
layout: default
title: Secured JWT signed with Symmetric Key Example
categories: [1.1]
---

##### Secured JWT signed with HS256 symmetric key example #####
See [Getting Started]({{ site.baseurl }}/1.1/docs/getting-started) for maven dependency and definition of `Claim`.

~~~
SymmetricKey key = new SymmetricKey(
    Optional.of("test-key-id"),
    KeyType.OCT,
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
);

AppFactory appFactory = new AppFactory();
SecureTokenBuilder secureTokenBuilder = appFactory.secureTokenBuilder(Algorithm.HS256, key);

Claim claim = new Claim();
claim.setUriIsRoot(true);

Token token = secureTokenBuilder.build(Algorithm.HS256, claim);

JwtSerializer jwtSerializer = appFactory.jwtSerializer();
String jwt = jwtSerializer.tokenToJwt(token);
~~~

The example above is documented in [JWS](https://tools.ietf.org/html/rfc7515#appendix-A.1)

- `key` represents a [JWK](https://tools.ietf.org/html/rfc7517) (JSON Web Key). 
- `KeyType.OCT` indicates it's a symmetric key, documented in [JSON Web Algorithms](https://tools.ietf.org/html/rfc7518#section-6.1) (JWA).
- The key value, `AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow` is the base64 encoded value of the key value. The key value is an octect sequence. Which is documented in [JWA](https://tools.ietf.org/html/rfc7518#section-6.4.1)

##### JWT to an instance of a Token - verify signature #####

~~~
JwtSerializer jwtSerializer = appFactory.jwtSerializer();
Token token = jwtSerializer.jwtToToken(jwt, Claim.class);

Key key = new Key();
key.setKeyType(KeyType.OCT);
key.setKey("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");

VerifySignatureFactory verifySignatureFactory = appConfig.verifySignatureFactory();
VerifySignature verifySignature = verifySignatureFactory.makeVerifySignature(Algorithm.HS256, key);

boolean isVerified = verifySignature.run(token);
~~~