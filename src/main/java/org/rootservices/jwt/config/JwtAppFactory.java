package org.rootservices.jwt.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.rootservices.jwt.jwe.serialization.direct.JweDirectDesializer;
import org.rootservices.jwt.jwe.serialization.direct.JweDirectSerializer;
import org.rootservices.jwt.jwe.serialization.rsa.JweRsaSerializer;
import org.rootservices.jwt.jws.serialization.SecureJwtSerializer;
import org.rootservices.jwt.exception.SignatureException;
import org.rootservices.jwt.serialization.JwtSerde;
import org.rootservices.jwt.serialization.Serdes;
import org.rootservices.jwt.serialization.UnSecureJwtSerializer;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.factory.CipherRSAFactory;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.jwk.PrivateKeyFactory;
import org.rootservices.jwt.jwk.PublicKeyFactory;
import org.rootservices.jwt.jwk.SecretKeyFactory;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import org.rootservices.jwt.serialization.HeaderDeserializer;
import org.rootservices.jwt.jwe.serialization.rsa.JweRsaDeserializer;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;
import org.rootservices.jwt.factory.SecureJwtFactory;
import org.rootservices.jwt.factory.UnSecureJwtFactory;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
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
import java.util.Base64;


public class JwtAppFactory {
    private static final Logger LOGGER = LogManager.getLogger(JwtAppFactory.class);
    public static final String KEY_WAS_INVALID = "Could not construct Signer. Key was invalid.";
    public static final String ALG_WAS_INVALID = "Could not construct Signer. Algorithm was invalid.";
    public static final String RSA = "RSA";
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

    public Serdes serdes() {
        return new Serdes(objectMapper());
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
        return new HeaderDeserializer(decoder(), serdes());
    }

    public JwtSerde jwtSerde() {
        return new JwtSerde(
                serdes(),
                encoder(),
                decoder()
        );
    }

    public CipherRSAFactory cipherRSAFactory() {
        return new CipherRSAFactory();
    }

    public CipherSymmetricFactory cipherSymmetricFactory() {
        return new CipherSymmetricFactory();
    }

    public JweRsaDeserializer jweRsaDeserializer() {

        return new JweRsaDeserializer(
                serdes(),
                urlDecoder(),
                privateKeyFactory(),
                cipherRSAFactory(),
                cipherSymmetricFactory()
        );
    }

    public JweDirectDesializer jweDirectDesializer() {
        return new JweDirectDesializer(
                serdes(),
                urlDecoder(),
                cipherSymmetricFactory()
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
                jwtSerde(),
                encoder()
        );
    }

    public VerifySignatureFactory verifySignatureFactory() {
        return new VerifySignatureFactory(signerFactory(), publicKeySignatureFactory(), urlDecoder());
    }

    public VerifySignature verifySignature(Algorithm algorithm, Key key) throws SignatureException {
        return verifySignatureFactory().makeVerifySignature(algorithm, key);
    }

    public UnSecureJwtFactory unsecureJwtFactory(){
        return new UnSecureJwtFactory();
    }

    public SecureJwtFactory secureJwtFactory(Algorithm alg, Key jwk) throws InvalidAlgorithmException, InvalidJsonWebKeyException {
        Signer signer = signerFactory().makeSigner(alg, jwk);
        return new SecureJwtFactory(signer, alg, jwk.getKeyId());
    }

    public SecureJwtSerializer secureJwtSerializer(Algorithm alg, Key jwk) throws SignatureException {
        SecureJwtFactory secureJwtFactory;
        try {
            secureJwtFactory = secureJwtFactory(alg, jwk);
        } catch (InvalidAlgorithmException e) {
            throw new SignatureException(ALG_WAS_INVALID, e);
        } catch (InvalidJsonWebKeyException e) {
            throw new SignatureException(KEY_WAS_INVALID, e);
        }

        JwtSerde jwtSerde = jwtSerde();

        return new SecureJwtSerializer(secureJwtFactory, jwtSerde);
    }

    public JweRsaSerializer jweRsaSerializer(RSAPublicKey jwk) throws PublicKeyException, CipherException {
        java.security.interfaces.RSAPublicKey jdkKey;
        try {
            jdkKey = publicKeyFactory().makePublicKey(jwk);
        } catch (PublicKeyException e) {
            throw e;
        }

        Cipher rsaEncryptCipher;
        try {
            rsaEncryptCipher = cipherRSAFactory().forEncrypt(Transformation.RSA_OAEP, jdkKey);
        } catch (CipherException e) {
            throw e;
        }

        return new JweRsaSerializer(
                serdes(),
                encoder(),
                rsaEncryptCipher,
                new SecretKeyFactory(),
                cipherSymmetricFactory()
        );
    }

    public JweDirectSerializer jweDirectSerializer() {

        return new JweDirectSerializer(
                serdes(),
                encoder(),
                cipherSymmetricFactory()
        );
    }

    public UnSecureJwtSerializer unSecureJwtSerializer() {
        return new UnSecureJwtSerializer(unsecureJwtFactory(), jwtSerde());
    }

    protected KeyFactory rsaKeyFactory() {
        if (this.RSAKeyFactory == null) {
            try {
                RSAKeyFactory = KeyFactory.getInstance(RSA);
            } catch (NoSuchAlgorithmException e) {
                // will never reach here.
                LOGGER.error(e.getMessage(), e);
            }
        }
        return RSAKeyFactory;
    }
}
