[JSON Web Tokens](https://tools.ietf.org/html/rfc7519)
---------------------------------------------------------------------------------------------------------------------

[![Build Status](https://travis-ci.org/TokenSmith/jwt.svg?branch=development)](https://travis-ci.org/TokenSmith/jwt)


Documentation
------------
 More documentation is available [here](http://tokensmith.github.io/jwt/).
 
Quick Start
-----------
This is a Java implementation of JWT, JWS, and JWE.

 - [Unsecured JWT](#unsecured-jwt)
 - [Read a compact JWT](#read-a-compact-jwt)
 - [Asymmetric Key](#asymmetric-key)
 - [Symmetric Key](#symmetric-key)
 - [Generate Key](#generate-key)
 
## Unsecured JWT
```java
UnsecureCompactBuilder compactBuilder = new UnsecureCompactBuilder();

Claim claim = new Claim();
claim.setUriIsRoot(true);

ByteArrayOutputStream encodedJwt = compactBuilder
    .claims(claim)
    .build();
```
## Read a compact JWT
```java
JwtAppFactory appFactory = new JwtAppFactory();

String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.TeZ3DKSE-gplbaoA8CK_RMojt8CfA1MTYaM_ZuOeGNw";
JwtSerde jwtSerde = appFactory.jwtSerde();

JsonWebToken<Claim> jsonWebToken;
try {
    jsonWebToken = jwtSerde.stringToJwt(jwt, Claim.class);
} catch (InvalidJWT | JsonToJwtException e) {
    // may not have been a jwt
    // may not have been able to deserialize the header or claims.
    throw e;
}

// Can access claims in, jsonWebToken.
```


## JWS Compact Serialization

### Asymmetric key

#### Create
```java
SecureCompactBuilder compactBuilder = new SecureCompactBuilder();

KeyGenerator keyGenerator = jwtAppFactory.keyGenerator();
SymmetricKey key = keyGenerator.symmetricKey(Optional.of(""test-key-id""), Use.SIGNATURE);

Claim claim = new Claim();
claim.setUriIsRoot(true);

ByteArrayOutputStream actual = compactBuilder.alg(Algorithm.RS256)
        .key(key)
        .claims(claim)
        .build();
```

#### Verify Signature
```java
RSAPublicKey publicKey = new RSAPublicKey(
    Optional.of("test-key-id"),
    Use.SIGNATURE,
    new BigInteger("20446702916744654562596343388758805860065209639960173505037453331270270518732245089773723012043203236097095623402044690115755377345254696448759605707788965848889501746836211206270643833663949992536246985362693736387185145424787922241585721992924045675229348655595626434390043002821512765630397723028023792577935108185822753692574221566930937805031155820097146819964920270008811327036286786392793593121762425048860211859763441770446703722015857250621107855398693133264081150697423188751482418465308470313958250757758547155699749157985955379381294962058862159085915015369381046959790476428631998204940879604226680285601"),
    new BigInteger("65537")
);

JwtAppFactory appFactory = new JwtAppFactory();
VerifySignature verifySignature;

try {
    verifySignature = appFactory.verifySignature(Algorithm.RS256, publicKey);
} catch (SignatureException e) {
    throw e;
}

boolean isSignatureValid = verifySignature.run(jsonWebToken);
```
### Symmetric key

#### Create
```java
SecureCompactBuilder compactBuilder = new SecureCompactBuilder();

SymmetricKey key = Factory.makeSymmetricKey();
key.setKeyId(Optional.of("test-key-id"));

Claim claim = new Claim();
claim.setUriIsRoot(true);

ByteArrayOutputStream actual = compactBuilder.alg(Algorithm.HS256)
        .key(key)
        .claims(claim)
        .build();
```
#### Verify Signature
```java
SymmetricKey key = new SymmetricKey(
    Optional.of("test-key-id"),
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    Use.SIGNATURE
);

JwtAppFactory appFactory = new JwtAppFactory();
VerifySignature verifySignature = null;
try {
    verifySignature = appFactory.verifySignature(Algorithm.HS256, key);
} catch (SignatureException e) {
    throw e;
}

boolean isSignatureValid = verifySignature.run(jsonWebToken);
```
## JWE Compact Serialization

### Asymmetric key

#### Create
```java
EncryptedCompactBuilder compactBuilder = new EncryptedCompactBuilder();

byte[] payload = "Help me, Obi-Wan Kenobi. You're my only hope.".getBytes();

RSAPublicKey publicKey = Factory.makeRSAPublicKeyForJWE();
publicKey.setKeyId(Optional.of(UUID.randomUUID().toString()));

ByteArrayOutputStream actual = compactBuilder.encAlg(EncryptionAlgorithm.AES_GCM_256)
        .alg(Algorithm.RSAES_OAEP)
        .payload(payload)
        .rsa(publicKey)
        .build();
```

### Symmetric key

#### Create
```java
EncryptedCompactBuilder compactBuilder = new EncryptedCompactBuilder();

SymmetricKey key = Factory.makeSymmetricKeyForJWE();

byte[] payload = "Help me, Obi-Wan Kenobi. You're my only hope.".getBytes();

ByteArrayOutputStream actual = compactBuilder.encAlg(EncryptionAlgorithm.AES_GCM_256)
        .alg(Algorithm.DIRECT)
        .encAlg(EncryptionAlgorithm.AES_GCM_256)
        .payload(payload)
        .cek(key)
        .build();
```

## Generate Key

### Symmetric Key
```java
JwtAppFactory jwtAppFactory = new JwtAppFactory();

KeyGenerator keyGenerator = jwtAppFactory.keyGenerator();
SymmetricKey key = keyGenerator.symmetricKey(Optional.of("123"), Use.SIGNATURE);
```

### Asymmetric Key
```java
JwtAppFactory jwtAppFactory = new JwtAppFactory();

KeyGenerator keyGenerator = jwtAppFactory.keyGenerator();
RSAKeyPair key = subject.rsaKeyPair(KeyGenerator.RSA_1024, Optional.of("123"), Use.SIGNATURE);
```
