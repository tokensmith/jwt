package org.rootservices.jwt.signer;

import org.rootservices.jwt.entity.jwk.Key;

import java.io.UnsupportedEncodingException;

/**
 * Created by tommackenzie on 8/19/15.
 */
public interface Signer {
    String run(byte[] signingInput);
}
