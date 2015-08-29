package org.rootservices.jwt.signature.signer;

import org.rootservices.jwt.entity.jwt.Token;

/**
 * Created by tommackenzie on 8/19/15.
 */
public interface Signer {
    String run(byte[] signingInput);
    String run(Token token);
}
