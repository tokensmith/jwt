package org.rootservices.jwt.signature.signer.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.Serializer;
import org.rootservices.jwt.signature.signer.MacSigner;
import org.rootservices.jwt.signature.signer.RSASigner;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.exception.SignerException;
import org.rootservices.jwt.signature.signer.factory.hmac.MacFactory;
import org.rootservices.jwt.signature.signer.factory.hmac.exception.MacException;
import org.rootservices.jwt.signature.signer.factory.rsa.PrivateKeySignatureFactory;


import javax.crypto.Mac;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/22/15.
 *
 * Creates a, Signer, which can be use to produce a signature for a JWT.
 */
public class SignerFactoryImpl implements SignerFactory {
    private MacFactory macFactory;
    private PrivateKeySignatureFactory privateKeySignatureFactory;
    private Base64.Encoder encoder;
    private JWTSerializer jwtSerializer;

    public SignerFactoryImpl(MacFactory macFactory, PrivateKeySignatureFactory privateKeySignatureFactory, JWTSerializer jwtSerializer, Base64.Encoder encoder){
        this.macFactory = macFactory;
        this.privateKeySignatureFactory = privateKeySignatureFactory;
        this.jwtSerializer = jwtSerializer;
        this.encoder = encoder;
    }

    @Override
    public Signer makeSigner(Algorithm alg, Key jwk) throws SignerException {
        Signer signer = null;
        if (jwk.getKeyType() == KeyType.OCT) {
            signer = makeMacSigner(alg, jwk);
        } else if ( jwk.getKeyType() == KeyType.RSA) {
            signer = makeRSASigner(alg, (RSAKeyPair) jwk);
        }
        return signer;
    }

    @Override
    public Signer makeMacSigner(Algorithm algorithm, Key key) throws SignerException {
        Mac mac = null;

        try {
            mac = macFactory.makeMac(algorithm, (SymmetricKey) key);
        } catch (MacException e) {
            throw new SignerException("Couldn't create signer", e);
        }

        return new MacSigner(jwtSerializer, mac, encoder);
    }

    private Signer makeRSASigner(Algorithm algorithm, RSAKeyPair keyPair) throws SignerException {
        Signature signature = null;
        try {
            signature = privateKeySignatureFactory.makeSignature(algorithm, keyPair);
        } catch (SignatureException e) {
            throw new SignerException("Couldn't create signer", e);
        }
        return new RSASigner(signature, jwtSerializer, encoder);
    }
}
