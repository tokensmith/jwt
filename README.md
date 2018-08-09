[JSON Web Tokens](https://tools.ietf.org/html/rfc7519)
---------------------------------------------------------------------------------------------------------------------

[![Build Status](https://travis-ci.org/RootServices/jwt.svg?branch=development)](https://travis-ci.org/RootServices/jwt)


Documentation
------------
 More documentation is available [here](http://rootservices.github.io/jwt/).
 
Quick Start
-----------
This is a Java implementation of JWT, JWS, and JWE.
 
## Unsecured JWT
```java
UnsecureCompactBuilder compactBuilder = new UnsecureCompactBuilder();

Claim claim = new Claim();
claim.setUriIsRoot(true);

ByteArrayOutputStream encodedJwt = compactBuilder.claims(claim).build();
```

## JWS Compact Serialization

### Asymmetric key
```java
SecureCompactBuilder compactBuilder = new SecureCompactBuilder();

RSAKeyPair key = Factory.makeRSAKeyPair();
key.setKeyId(Optional.of("test-key-id"));

Claim claim = new Claim();
claim.setUriIsRoot(true);

ByteArrayOutputStream actual = subject.alg(Algorithm.RS256)
        .key(key)
        .claims(claim)
        .build();
```

### Symmetric key
```java
SecureCompactBuilder compactBuilder = new SecureCompactBuilder();

SymmetricKey key = Factory.makeSymmetricKey();
key.setKeyId(Optional.of("test-key-id"));

Claim claim = new Claim();
claim.setUriIsRoot(true);

ByteArrayOutputStream actual = subject.alg(Algorithm.HS256)
        .key(key)
        .claims(claim)
        .build();
```

## JWE Compact Serialization
### Symmetric key
```java
SymmetricKey key = Factory.makeSymmetricKeyForJWE();

byte[] payload = "Help me, Obi-Wan Kenobi. You're my only hope.".getBytes();

ByteArrayOutputStream actual = subject.encAlg(EncryptionAlgorithm.AES_GCM_256)
        .alg(Algorithm.DIRECT)
        .encAlg(EncryptionAlgorithm.AES_GCM_256)
        .payload(payload)
        .cek(key)
        .build();
```

### Asymmetric key
```java
JwtAppFactory jwtAppFactory = new JwtAppFactory();

byte[] payload = "Help me, Obi-Wan Kenobi. You're my only hope.".getBytes();

RSAPublicKey publicKey = Factory.makeRSAPublicKeyForJWE();
publicKey.setKeyId(Optional.of(UUID.randomUUID().toString()));

ByteArrayOutputStream actual = subject.encAlg(EncryptionAlgorithm.AES_GCM_256)
        .alg(Algorithm.RSAES_OAEP)
        .payload(payload)
        .rsa(publicKey)
        .build();
```
