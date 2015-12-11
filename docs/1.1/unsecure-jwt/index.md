---
layout: default
title: Unsecured JWT Example
---

See [Getting Started]({{ site.baseurl }}/1.1/docs/getting-started) for maven dependency and definition of `Claim`.

~~~
AppFactory appFactory = new AppFactory();
UnsecureTokenBuilder unsecureTokenBuilder = appFactory.unsecureTokenBuilder();

Claim claim = new Claim();
claim.setUriIsRoot(true);

Token token = unsecureTokenBuilder.build(claim);

JwtSerializer jwtSerializer = appFactory.jwtSerializer();
String jwt = jwtSerializer.tokenToJwt(token);
~~~