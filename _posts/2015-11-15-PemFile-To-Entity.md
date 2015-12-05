---
layout: default
title: Pem file to RSAKeyPair
date: 2015-11-15 11:59:54
---

##### Translate a pem file (private key) to a RSAKeyPair #####

~~~
AppFactory appFactory = new AppFactory();
PemToRSAKeyPair pemToRSAKeyPair = appFactory.pemToRSAKeyPair();

URL privateKeyURL = new URL("file:///example/rsa-private-key.pem")

FileReader pemFileReader = null;
try {
    pemFileReader = new FileReader(privateKeyURL.getFile());
} catch (FileNotFoundException e) {
    e.printStackTrace();
}

RSAKeyPair rsaKeyPair = pemToRSAKeyPair.translate(pemFileReader, Optional.of("test-key-id"), Use.SIGNATURE);
~~~