---
layout: default
title:  CSR file to RSAPublicKey
date: 2015-11-15 11:59:53
---

##### Translate a csr file to a RSAPublicKey #####

~~~
AppFactory appFactory = new AppFactory();
CSRToRSAPublicKey csrToRSAPublicKey = appFactory.csrToRSAPublicKey();

URL privateKeyURL = new URL("file:///example/rsa-cert.csr")

FileReader fr = new FileReader(privateKeyURL.getFile());
RSAPublicKey rsaPublicKey = subject.translate(fr, Optional.of("test-key-id"), Use.SIGNATURE);
~~~