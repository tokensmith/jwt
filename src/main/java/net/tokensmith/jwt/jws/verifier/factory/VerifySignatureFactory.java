package net.tokensmith.jwt.jws.verifier.factory;

import net.tokensmith.jwt.entity.jwk.Key;
import net.tokensmith.jwt.entity.jwk.KeyType;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.exception.SignatureException;
import net.tokensmith.jwt.jws.signer.SignAlgorithm;
import net.tokensmith.jwt.jws.signer.Signer;
import net.tokensmith.jwt.jws.signer.factory.SignerFactory;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;
import net.tokensmith.jwt.jws.signer.factory.rsa.PublicKeySignatureFactory;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.RSAPublicKeyException;
import net.tokensmith.jwt.jws.verifier.VerifyMacSignature;
import net.tokensmith.jwt.jws.verifier.VerifyRsaSignature;
import net.tokensmith.jwt.jws.verifier.VerifySignature;

import java.security.Signature;
import java.util.Base64.Decoder;

/**
 * Created by tommackenzie on 11/14/15.
 */
public class VerifySignatureFactory {
    public static final String ALG_WAS_INVALID = "Could not construct Signer. Algorithm was invalid.";
    public static final String KEY_WAS_INVALID = "Could not construct Signer. Key was invalid.";
    private SignerFactory signerFactory;
    private PublicKeySignatureFactory publicKeySignatureFactory;
    private Decoder decoder;

    public VerifySignatureFactory(SignerFactory signerFactory, PublicKeySignatureFactory publicKeySignatureFactory, Decoder decoder) {
        this.signerFactory = signerFactory;
        this.publicKeySignatureFactory = publicKeySignatureFactory;
        this.decoder = decoder;
    }

    public VerifySignature makeVerifySignature(Algorithm algorithm, Key key) throws SignatureException {
        VerifySignature verifySignature = null;

        if (key.getKeyType() == KeyType.OCT) {
            verifySignature = makeVerifyMacSignature(algorithm, (SymmetricKey) key);
        } else if (key.getKeyType() == KeyType.RSA){
            verifySignature =  makeVerifyRsaSignature(algorithm, (RSAPublicKey) key);
        }
        return verifySignature;
    }

    private VerifySignature makeVerifyMacSignature(Algorithm algorithm, SymmetricKey key) throws SignatureException {
        Signer macSigner;
        try {
            macSigner = signerFactory.makeMacSigner(algorithm, key);
        } catch (InvalidAlgorithmException e) {
            throw new SignatureException(ALG_WAS_INVALID, e);
        } catch (InvalidJsonWebKeyException e) {
            throw new SignatureException(KEY_WAS_INVALID, e);
        }

        return new VerifyMacSignature(macSigner);
    }

    private VerifySignature makeVerifyRsaSignature(Algorithm algorithm, RSAPublicKey key) throws SignatureException {
        Signature signature;

        SignAlgorithm signAlgorithm = SignAlgorithm.valueOf(algorithm.getValue());

        try {
            signature = publicKeySignatureFactory.makeSignature(signAlgorithm, key);
        } catch (InvalidAlgorithmException e) {
            throw new SignatureException(ALG_WAS_INVALID, e);
        } catch (InvalidJsonWebKeyException | RSAPublicKeyException e) {
            throw new SignatureException(KEY_WAS_INVALID, e);
        }

        return new VerifyRsaSignature(signature, decoder);
    }
}
