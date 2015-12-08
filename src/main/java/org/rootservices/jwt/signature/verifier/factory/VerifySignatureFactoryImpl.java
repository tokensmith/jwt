package org.rootservices.jwt.signature.verifier.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.exception.SignerException;
import org.rootservices.jwt.signature.signer.factory.rsa.PublicKeySignatureFactory;
import org.rootservices.jwt.signature.signer.factory.SignerFactory;
import org.rootservices.jwt.signature.verifier.VerifyMacSignature;
import org.rootservices.jwt.signature.verifier.VerifyRsaSignature;
import org.rootservices.jwt.signature.verifier.VerifySignature;

import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64.Decoder;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class VerifySignatureFactoryImpl implements VerifySignatureFactory {

    private SignerFactory signerFactory;
    private PublicKeySignatureFactory publicKeySignatureFactory;
    private Decoder decoder;

    public VerifySignatureFactoryImpl(SignerFactory signerFactory, PublicKeySignatureFactory publicKeySignatureFactory, Decoder decoder) {
        this.signerFactory = signerFactory;
        this.publicKeySignatureFactory = publicKeySignatureFactory;
        this.decoder = decoder;
    }

    public VerifySignature makeVerifySignature(Algorithm algorithm, Key key) throws SignerException, SignatureException {
        VerifySignature verifySignature = null;

        if (key.getKeyType() == KeyType.OCT) {
            Signer macSigner = signerFactory.makeMacSigner(algorithm, (SymmetricKey)key);
            verifySignature = new VerifyMacSignature(macSigner);
        } else if (key.getKeyType() == KeyType.RSA){
            Signature signature = publicKeySignatureFactory.makeSignature(Algorithm.RS256, (RSAPublicKey)key);
            verifySignature =  new VerifyRsaSignature(signature, decoder);
        }
        return verifySignature;
    }
}
