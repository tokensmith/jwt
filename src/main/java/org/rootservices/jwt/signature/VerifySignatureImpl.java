package org.rootservices.jwt.signature;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.Token;
import org.rootservices.jwt.entity.jwt.header.Algorithm;


/**
 * Created by tommackenzie on 8/26/15.
 */
public class VerifySignatureImpl implements VerifySignature {

    @Override
    public boolean run(Token token, Key jwk) {


        return false;
    }

    @Override
    public boolean run(byte[] signInput, Algorithm alg, String signature, Key jwk) {
        return false;
    }
}
