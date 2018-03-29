package org.rootservices.jwt.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.rootservices.jwt.jwe.serialization.JWESerializer;
import org.rootservices.jwt.jws.serialization.SecureJwtSerializer;
import org.rootservices.jwt.serialization.UnSecureJwtSerializer;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.factory.CipherRSAFactory;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.jwk.PrivateKeyFactory;
import org.rootservices.jwt.jwk.PublicKeyFactory;
import org.rootservices.jwt.jwk.SecretKeyFactory;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import org.rootservices.jwt.serialization.HeaderDeserializer;
import org.rootservices.jwt.jwe.serialization.JWEDeserializer;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PrivateKeyException;
import org.rootservices.jwt.factory.SecureJwtFactory;
import org.rootservices.jwt.factory.UnSecureJwtFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serialization.JWTDeserializer;
import org.rootservices.jwt.serialization.Serializer;
import org.rootservices.jwt.jws.signer.factory.hmac.MacFactory;
import org.rootservices.jwt.jws.signer.factory.rsa.PrivateKeySignatureFactory;
import org.rootservices.jwt.jws.signer.factory.rsa.PublicKeySignatureFactory;
import org.rootservices.jwt.jws.verifier.VerifySignature;
import org.rootservices.jwt.jws.signer.Signer;
import org.rootservices.jwt.jws.signer.factory.*;
import org.rootservices.jwt.jws.verifier.factory.VerifySignatureFactory;


import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

/**
 * Created by tommackenzie on 8/13/15.
 */
public class JwtAppFactory {
    private static final Logger LOGGER = LogManager.getLogger(JwtAppFactory.class);
    private static ObjectMapper objectMapper;
    private static KeyFactory RSAKeyFactory;

    public ObjectMapper objectMapper() {
        if (objectMapper == null) {
            this.objectMapper = new ObjectMapper()
                    .setPropertyNamingStrategy(
                            PropertyNamingStrategy.SNAKE_CASE
                    )
                    .configure(JsonParser.Feature.STRICT_DUPLICATE_DETECTION, true)
                    .registerModule(new Jdk8Module())
                    .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                    .setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
        }
        return objectMapper;
    }

    public Serializer serializer() {
        return new Serializer(objectMapper());
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

    public HeaderDeserializer headerDeserializer() {
        return new HeaderDeserializer(decoder(), serializer());
    }

    public JWTDeserializer jwtDeserializer() {
        return new JWTDeserializer(
                serializer(),
                encoder(),
                decoder()
        );
    }

    public CipherRSAFactory cipherRSAFactory() {
        return new CipherRSAFactory();
    }

    public SecretKeyFactory secretKeyFactory() {
        return new SecretKeyFactory();
    }

    public JWEDeserializer jweDeserializer(RSAKeyPair jwk) throws PrivateKeyException, CipherException {
        RSAPrivateCrtKey key = privateKeyFactory().makePrivateKey(jwk);
        Cipher rsaDecryptCipher = cipherRSAFactory().forDecrypt(Transformation.RSA_OAEP, key);
        return new JWEDeserializer(
                serializer(),
                urlDecoder(),
                rsaDecryptCipher,
                secretKeyFactory(),
                new CipherSymmetricFactory()
        );
    }

    public PublicKeyFactory publicKeyFactory() {
        return new PublicKeyFactory(rsaKeyFactory());
    }

    public PublicKeySignatureFactory publicKeySignatureFactory() {
        return new PublicKeySignatureFactory(rsaKeyFactory());
    }

    public MacFactory macFactory() {
        return new MacFactory(urlDecoder());
    }

    public PrivateKeyFactory privateKeyFactory() {
        return new PrivateKeyFactory(rsaKeyFactory());
    }

    public PrivateKeySignatureFactory privateKeySignatureFactory() {
        return new PrivateKeySignatureFactory(rsaKeyFactory());
    }

    public SignerFactory signerFactory() {
        return new SignerFactory(
                macFactory(),
                privateKeySignatureFactory(),
                jwtDeserializer(),
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

    public SecureJwtSerializer secureJwtEncoder(Algorithm alg, Key jwk) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        SecureJwtFactory secureJwtFactory;
        try {
            secureJwtFactory = secureJwtFactory(alg, jwk);
        } catch (InvalidAlgorithmException e) {
            throw e;
        } catch (InvalidJsonWebKeyException e) {
            throw e;
        }

        JWTDeserializer jwtDeserializer = jwtDeserializer();

        return new SecureJwtSerializer(secureJwtFactory, jwtDeserializer);
    }

    public JWESerializer jweEncoder(RSAPublicKey jwk) throws PublicKeyException, CipherException {
        java.security.interfaces.RSAPublicKey jdkKey = publicKeyFactory().makePublicKey(jwk);
        Cipher rsaEncryptCipher = cipherRSAFactory().forEncrypt(Transformation.RSA_OAEP, jdkKey);
        return new JWESerializer(
                serializer(),
                encoder(),
                rsaEncryptCipher,
                new SecretKeyFactory(),
                new CipherSymmetricFactory()
        );
    }

    public UnSecureJwtSerializer unSecureJwtEncoder() {
        return new UnSecureJwtSerializer(unsecureJwtFactory(), jwtDeserializer());
    }

    protected KeyFactory rsaKeyFactory() {
        if (this.RSAKeyFactory == null) {
            try {
                RSAKeyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                // will never reach here.
                LOGGER.error(e.getMessage(), e);
            }
        }
        return RSAKeyFactory;
    }
}
