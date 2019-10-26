package net.tokensmith.jwt.jws.signer.factory;

import net.tokensmith.jwt.entity.jwk.Key;
import net.tokensmith.jwt.entity.jwk.KeyType;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.jws.signer.MacSigner;
import net.tokensmith.jwt.jws.signer.RSASigner;
import net.tokensmith.jwt.jws.signer.SignAlgorithm;
import net.tokensmith.jwt.jws.signer.Signer;
import net.tokensmith.jwt.serialization.JwtSerde;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;
import net.tokensmith.jwt.jws.signer.factory.hmac.MacFactory;
import net.tokensmith.jwt.jws.signer.factory.hmac.exception.SecurityKeyException;
import net.tokensmith.jwt.jws.signer.factory.rsa.PrivateKeySignatureFactory;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PrivateKeyException;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.RSAPrivateKeyException;


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
    private JwtSerde jwtSerde;

    public SignerFactory(MacFactory macFactory, PrivateKeySignatureFactory privateKeySignatureFactory, JwtSerde jwtSerde, Base64.Encoder encoder){
        this.macFactory = macFactory;
        this.privateKeySignatureFactory = privateKeySignatureFactory;
        this.jwtSerde = jwtSerde;
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

        return new MacSigner(jwtSerde, mac, encoder);
    }

    private Signer makeRSASigner(Algorithm alg, RSAKeyPair keyPair) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        Signature signature;

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
        return new RSASigner(signature, jwtSerde, encoder);
    }
}
