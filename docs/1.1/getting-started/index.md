---
layout: default
title: Getting started
---

### {{ page.title }} ###

A basic understanding of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) (JWT) 
and [JSON Web Signatures](https://tools.ietf.org/html/rfc7515) (JWS) is recommended.

##### Maven dependency #####

~~~
<dependency>
    <groupId>org.rootservices</groupId>
    <artifactId>jwt</artifactId>
    <version>{{ site.latest_release }}</version>
</dependency>
~~~

##### Extend the Claim class to add claims #####

~~~
package com.organization.project;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.rootservices.jwt.entity.jwt.Claims;

/**
 * Created by tommackenzie on 8/11/15.
 */
public class Claim extends Claims {
    @JsonProperty(value="http://example.com/is_root")
    private Boolean uriIsRoot;

    public Boolean isUriIsRoot() {
        return uriIsRoot;
    }

    public void setUriIsRoot(Boolean uriIsRoot) {
        this.uriIsRoot = uriIsRoot;
    }
}
~~~