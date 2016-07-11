package org.rootservices.jwt.signature.verifier.factory;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.KeyType;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.signature.signer.SignAlgorithm;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebKeyException;
import org.rootservices.jwt.signature.signer.factory.SignerFactory;
import org.rootservices.jwt.signature.signer.factory.rsa.PublicKeySignatureFactory;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.PublicKeyException;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.RSAPublicKeyException;
import org.rootservices.jwt.signature.verifier.VerifyMacSignature;
import org.rootservices.jwt.signature.verifier.VerifyRsaSignature;
import org.rootservices.jwt.signature.verifier.VerifySignature;

import java.security.Signature;
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

    public VerifySignature makeVerifySignature(Algorithm algorithm, Key key) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        VerifySignature verifySignature = null;

        if (key.getKeyType() == KeyType.OCT) {
            verifySignature = makeVerifyMacSignature(algorithm, key);
        } else if (key.getKeyType() == KeyType.RSA){
            verifySignature =  makeVerifyRsaSignature(algorithm, (RSAPublicKey) key);
        }
        return verifySignature;
    }

    private VerifySignature makeVerifyMacSignature(Algorithm algorithm, Key key) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        Signer macSigner = signerFactory.makeMacSigner(algorithm, key);
        return new VerifyMacSignature(macSigner);
    }

    private VerifySignature makeVerifyRsaSignature(Algorithm algorithm, RSAPublicKey key) throws InvalidJsonWebKeyException, InvalidAlgorithmException {
        Signature signature;

        try {
            signature = publicKeySignatureFactory.makeSignature(SignAlgorithm.RS256, key);
        } catch (PublicKeyException e) {
            throw new InvalidJsonWebKeyException("", e);
        } catch (RSAPublicKeyException e) {
            throw new InvalidJsonWebKeyException("", e);
        } catch (InvalidAlgorithmException e) {
            throw e;
        }

        return new VerifyRsaSignature(signature, decoder);
    }
}
