package org.rootservices.jwt.signature.signer.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.Serializer;
import org.rootservices.jwt.signature.signer.MacSigner;
import org.rootservices.jwt.signature.signer.RSASigner;
import org.rootservices.jwt.signature.signer.Signer;


import javax.crypto.Mac;
import java.security.Signature;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/22/15.
 *
 * Creates a, Signer, which can be use to produce a signature for a JWT.
 */
public class SignerFactoryImpl implements SignerFactory {
    private MacFactory macFactory;
    private PrivateKeySignatureFactory privateKeySignatureFactory;
    private Serializer serializer;
    private Base64.Encoder encoder;

    public SignerFactoryImpl(MacFactory macFactory, PrivateKeySignatureFactory privateKeySignatureFactory, Serializer serializer, Base64.Encoder encoder){
        this.macFactory = macFactory;
        this.privateKeySignatureFactory = privateKeySignatureFactory;
        this.serializer = serializer;
        this.encoder = encoder;
    }

    @Override
    public Signer makeSigner(Algorithm alg, Key jwk) {
        Signer signer = null;
        if (alg == Algorithm.HS256) {
            signer = makeMacSigner(alg, jwk);
        } else if ( alg == Algorithm.RS256) {
            signer = makeRSASigner(alg, (RSAKeyPair) jwk);
        }
        return signer;
    }

    @Override
    public Signer makeMacSigner(Algorithm algorithm, Key key) {
        Mac mac = macFactory.makeMac(algorithm, (SymmetricKey) key);
        return new MacSigner(serializer, mac, encoder);
    }

    private Signer makeRSASigner(Algorithm algorithm, RSAKeyPair keyPair) {
        Signature signature = privateKeySignatureFactory.makeSignature(algorithm, keyPair);
        return new RSASigner(signature, serializer, encoder);
    }
}
