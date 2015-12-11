---
layout: default
title:  CSR file to RSAPublicKey
categories: [1.1]
---

##### Translate a csr file to a RSAPublicKey #####

~~~
AppFactory appFactory = new AppFactory();
CSRToRSAPublicKey csrToRSAPublicKey = appFactory.csrToRSAPublicKey();

URL privateKeyURL = new URL("file:///example/rsa-cert.csr")

FileReader fr = new FileReader(privateKeyURL.getFile());
RSAPublicKey rsaPublicKey = subject.translate(fr, Optional.of("test-key-id"), Use.SIGNATURE);
~~~