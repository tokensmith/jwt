---
layout: default
title: Releases
---

### {{ page.title }} ###

#### 1.2 - Published on, 2016-09-03 ####
 - Single interface to produce a jwt
   - SecureJwtEncoder which given a claim will return a secure encoded jwt
   - UnSecureJwtEncoder which given a claim will return a encoded jwt

#### 1.1 - Published on, 2015-12-30 ####
 - Sign a JWT with RSASSA-PKCS1-v1_5 SHA-256
 - Verify a RSASSA-PKCS1-v1_5 SHA-256 signature
 - Renamed Token to JsonWebToken
 - Renamed interfaces that reference Token to Jwt.
 - Jose Header has the optional key, "kid" (Key Id).

#### 1.0 - Published on, 2015-09-20 ####
- Marshal a JWT to a [token](https://github.com/RootServices/jwt/blob/development/src/main/java/org/rootservices/jwt/entity/jwt/Token.java)
- Verify a secure token's signature with symmetric signing.
- Create an unsecure token
- Marshal a unsecure token to a JWT
- Create a secure token with symmetric signing.
- Marshal a secure token to a JWT
- Sign with HMAC SHA-256 algorithm
