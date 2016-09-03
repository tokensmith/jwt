package org.rootservices.jwt.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.rootservices.jwt.factory.IdTokenToJwt;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebKeyException;
import org.rootservices.jwt.translator.CSRToRSAPublicKey;
import org.rootservices.jwt.translator.PemToRSAKeyPair;
import org.rootservices.jwt.factory.SecureJwtFactory;
import org.rootservices.jwt.factory.UnSecureJwtFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.JWTSerializerImpl;
import org.rootservices.jwt.serializer.Serializer;
import org.rootservices.jwt.serializer.SerializerImpl;
import org.rootservices.jwt.signature.signer.factory.hmac.MacFactory;
import org.rootservices.jwt.signature.signer.factory.rsa.PrivateKeySignatureFactory;
import org.rootservices.jwt.signature.signer.factory.rsa.PublicKeySignatureFactory;
import org.rootservices.jwt.signature.verifier.VerifySignature;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.*;
import org.rootservices.jwt.signature.verifier.factory.VerifySignatureFactory;


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
        return new PublicKeySignatureFactory(rsaKeyFactory());
    }

    public MacFactory macFactory() {
        return new MacFactory(urlDecoder());
    }

    public PrivateKeySignatureFactory privateKeySignatureFactory() {
        return new PrivateKeySignatureFactory(rsaKeyFactory());
    }

    public SignerFactory signerFactory() {
        return new SignerFactory(
                macFactory(),
                privateKeySignatureFactory(),
                jwtSerializer(),
                encoder()
        );
    }

    public VerifySignatureFactory verifySignatureFactory() {
        return new VerifySignatureFactory(signerFactory(), publicKeySignatureFactory(), urlDecoder());
    }

    public VerifySignature verifySignature(Algorithm algorithm, Key key) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        return verifySignatureFactory().makeVerifySignature(algorithm, key);
    }

    public UnSecureJwtFactory unsecureJwtFactory(){
        return new UnSecureJwtFactory();
    }

    public SecureJwtFactory secureJwtFactory(Algorithm alg, Key jwk) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        Signer signer = signerFactory().makeSigner(alg, jwk);
        return new SecureJwtFactory(signer, alg, jwk.getKeyId());
    }

    public IdTokenToJwt idTokenToJwt(Algorithm alg, Key jwk) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        SecureJwtFactory secureJwtFactory = null;
        try {
            secureJwtFactory = secureJwtFactory(alg, jwk);
        } catch (InvalidAlgorithmException e) {
            throw e;
        } catch (InvalidJsonWebKeyException e) {
            throw e;
        }

        JWTSerializer jwtSerializer = jwtSerializer();

        return new IdTokenToJwt(secureJwtFactory, jwtSerializer);

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
