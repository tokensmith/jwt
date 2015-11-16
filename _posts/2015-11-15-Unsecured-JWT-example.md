---
layout: default
title: Unsecured JWT Example
date: 2015-11-15 11:59:57
---

~~~
AppFactory appFactory = new AppFactory();
UnsecureTokenBuilder unsecureTokenBuilder = appFactory.unsecureTokenBuilder();

Claim claim = new Claim();
claim.setUriIsRoot(true);

Token token = unsecureTokenBuilder.build(claim);

JwtSerializer jwtSerializer = appFactory.jwtSerializer();
String jwt = jwtSerializer.tokenToJwt(token);
~~~