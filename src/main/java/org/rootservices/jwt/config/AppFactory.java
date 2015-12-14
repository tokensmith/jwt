package org.rootservices.jwt.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.rootservices.jwt.config.exception.DependencyException;
import org.rootservices.jwt.signature.signer.factory.exception.SignerException;
import org.rootservices.jwt.signature.signer.factory.rsa.exception.SignatureException;
import org.rootservices.jwt.translator.CSRToRSAPublicKey;
import org.rootservices.jwt.translator.PemToRSAKeyPair;
import org.rootservices.jwt.builder.SecureJwtBuilder;
import org.rootservices.jwt.builder.UnsecureJwtBuilder;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.JWTSerializerImpl;
import org.rootservices.jwt.serializer.Serializer;
import org.rootservices.jwt.serializer.SerializerImpl;
import org.rootservices.jwt.signature.signer.factory.hmac.MacFactory;
import org.rootservices.jwt.signature.signer.factory.hmac.MacFactoryImpl;
import org.rootservices.jwt.signature.signer.factory.rsa.PrivateKeySignatureFactory;
import org.rootservices.jwt.signature.signer.factory.rsa.PrivateKeySignatureFactoryImpl;
import org.rootservices.jwt.signature.signer.factory.rsa.PublicKeySignatureFactory;
import org.rootservices.jwt.signature.signer.factory.rsa.PublicKeySignatureFactoryImpl;
import org.rootservices.jwt.signature.verifier.VerifySignature;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.*;
import org.rootservices.jwt.signature.verifier.factory.VerifySignatureFactory;
import org.rootservices.jwt.signature.verifier.factory.VerifySignatureFactoryImpl;


import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/13/15.
 */
public class AppFactory {

    public ObjectMapper objectMapper() {
        return new ObjectMapper()
                .setPropertyNamingStrategy(
                        PropertyNamingStrategy.CAMEL_CASE_TO_LOWER_CASE_WITH_UNDERSCORES
                )
                .configure(JsonParser.Feature.STRICT_DUPLICATE_DETECTION, true)
                .registerModule(new Jdk8Module())
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    }

    public Serializer serializer() {
        return new SerializerImpl(objectMapper());
    }

    public Base64.Decoder decoder() {
        return Base64.getDecoder();
    }

    public Base64.Decoder urlDecoder() {
        return Base64.getUrlDecoder();
    }

    public Base64.Encoder encoder() {
        return Base64.getUrlEncoder().withoutPadding();
    }

    public JWTSerializer jwtSerializer() {
        return new JWTSerializerImpl(
                serializer(),
                encoder(),
                decoder()
        );
    }

    public PublicKeySignatureFactory publicKeySignatureFactory() {
        return new PublicKeySignatureFactoryImpl(rsaKeyFactory());
    }

    public MacFactory macFactory() {
        return new MacFactoryImpl(urlDecoder());
    }

    public PrivateKeySignatureFactory privateKeySignatureFactory() {
        return new PrivateKeySignatureFactoryImpl(rsaKeyFactory());
    }

    public SignerFactory signerFactory() {
        return new SignerFactoryImpl(
                macFactory(),
                privateKeySignatureFactory(),
                jwtSerializer(),
                encoder()
        );
    }

    public VerifySignatureFactory verifySignatureFactory() {
        return new VerifySignatureFactoryImpl(signerFactory(), publicKeySignatureFactory(), urlDecoder());
    }

    public VerifySignature verifySignature(Algorithm algorithm, Key key) throws DependencyException {
        VerifySignature verifySignature = null;
        try {
            verifySignature = verifySignatureFactory().makeVerifySignature(algorithm, key);
        } catch (SignerException e) {
            throw new DependencyException("Could not create dependency, Signer", e);
        } catch (SignatureException e) {
            throw new DependencyException("Could not create dependency, Signature", e);
        }

        return verifySignature;
    }

    public UnsecureJwtBuilder unsecureJwtBuilder(){
        return new UnsecureJwtBuilder();
    }

    public SecureJwtBuilder secureJwtBuilder(Algorithm alg, Key jwk) throws DependencyException {
        Signer signer = null;
        try {
            signer = signerFactory().makeSigner(alg, jwk);
        } catch (SignerException e) {
            throw new DependencyException("Could not create dependency, Signer", e);
        }
        return new SecureJwtBuilder(signer);
    }

    public JcaPEMKeyConverter jcaPEMKeyConverter() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        return new JcaPEMKeyConverter().setProvider("BC");
    }

    protected KeyFactory rsaKeyFactory() {
        KeyFactory RSAKeyFactory = null;
        try {
            RSAKeyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            // will never reach here.
            e.printStackTrace();
        }
        return RSAKeyFactory;
    }

    public PemToRSAKeyPair pemToRSAKeyPair() {
        return new PemToRSAKeyPair(jcaPEMKeyConverter(), rsaKeyFactory());
    }

    public CSRToRSAPublicKey csrToRSAPublicKey() {
        return new CSRToRSAPublicKey();
    }
}
