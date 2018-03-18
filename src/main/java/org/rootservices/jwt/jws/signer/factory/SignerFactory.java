package org.rootservices.jwt.jws.signer.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.jws.signer.MacSigner;
import org.rootservices.jwt.jws.signer.RSASigner;
import org.rootservices.jwt.jws.signer.SignAlgorithm;
import org.rootservices.jwt.jws.signer.Signer;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;
import org.rootservices.jwt.jws.signer.factory.hmac.MacFactory;
import org.rootservices.jwt.jws.signer.factory.hmac.exception.SecurityKeyException;
import org.rootservices.jwt.jws.signer.factory.rsa.PrivateKeySignatureFactory;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PrivateKeyException;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.RSAPrivateKeyException;


import javax.crypto.Mac;
import java.security.Signature;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/22/15.
 *
 * Creates a, Signer, which can be use to produce a signature for a JWT.
 */
public class SignerFactory {
    private MacFactory macFactory;
    private PrivateKeySignatureFactory privateKeySignatureFactory;
    private Base64.Encoder encoder;
    private JWTSerializer jwtSerializer;

    public SignerFactory(MacFactory macFactory, PrivateKeySignatureFactory privateKeySignatureFactory, JWTSerializer jwtSerializer, Base64.Encoder encoder){
        this.macFactory = macFactory;
        this.privateKeySignatureFactory = privateKeySignatureFactory;
        this.jwtSerializer = jwtSerializer;
        this.encoder = encoder;
    }

    public Signer makeSigner(Algorithm alg, Key jwk) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        Signer signer = null;

        if (jwk.getKeyType() == KeyType.OCT) {
            signer = makeMacSigner(alg, jwk);
        } else if ( jwk.getKeyType() == KeyType.RSA) {
            signer = makeRSASigner(alg, (RSAKeyPair) jwk);
        }
        return signer;
    }

    public Signer makeMacSigner(Algorithm alg, Key key) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        Mac mac;
        SignAlgorithm signAlgorithm = SignAlgorithm.valueOf(alg.getValue());

        try {
            mac = macFactory.makeMac(signAlgorithm, (SymmetricKey) key);
        } catch (SecurityKeyException e) {
            throw new InvalidJsonWebKeyException("", e);
        } catch (InvalidAlgorithmException e) {
            throw e;
        }

        return new MacSigner(jwtSerializer, mac, encoder);
    }

    private Signer makeRSASigner(Algorithm alg, RSAKeyPair keyPair) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        Signature signature = null;

        SignAlgorithm signAlgorithm = SignAlgorithm.valueOf(alg.getValue());

        try {
            signature = privateKeySignatureFactory.makeSignature(signAlgorithm, keyPair);
        } catch (PrivateKeyException e) {
            throw new InvalidJsonWebKeyException("", e);
        } catch (RSAPrivateKeyException e) {
            throw new InvalidJsonWebKeyException("", e);
        } catch (InvalidAlgorithmException e) {
            throw e;
        }
        return new RSASigner(signature, jwtSerializer, encoder);
    }
}
