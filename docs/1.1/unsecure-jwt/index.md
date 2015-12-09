---
layout: default
title: Unsecured JWT Example
---

See [Getting Started]({{ site.baseurl }}{% post_url 2015-11-15-Getting-started %}) for maven dependency and definition of `Claim`.

~~~
AppFactory appFactory = new AppFactory();
UnsecureTokenBuilder unsecureTokenBuilder = appFactory.unsecureTokenBuilder();

Claim claim = new Claim();
claim.setUriIsRoot(true);

Token token = unsecureTokenBuilder.build(claim);

JwtSerializer jwtSerializer = appFactory.jwtSerializer();
String jwt = jwtSerializer.tokenToJwt(token);
~~~