package net.tokensmith.jwt.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import net.tokensmith.jwt.entity.jwk.Key;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.exception.SignatureException;
import net.tokensmith.jwt.factory.SecureJwtFactory;
import net.tokensmith.jwt.factory.UnSecureJwtFactory;
import net.tokensmith.jwt.jwe.Transformation;
import net.tokensmith.jwt.jwe.factory.CipherRSAFactory;
import net.tokensmith.jwt.jwe.factory.CipherSymmetricFactory;
import net.tokensmith.jwt.jwe.factory.exception.CipherException;
import net.tokensmith.jwt.jwe.serialization.direct.JweDirectDesializer;
import net.tokensmith.jwt.jwe.serialization.direct.JweDirectSerializer;
import net.tokensmith.jwt.jwe.serialization.rsa.JweRsaDeserializer;
import net.tokensmith.jwt.jwe.serialization.rsa.JweRsaSerializer;
import net.tokensmith.jwt.jwk.PrivateKeyTranslator;
import net.tokensmith.jwt.jwk.PublicKeyTranslator;
import net.tokensmith.jwt.jwk.SecretKeyFactory;
import net.tokensmith.jwt.jws.signer.Signer;
import net.tokensmith.jwt.jws.signer.factory.SignerFactory;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidAlgorithmException;
import net.tokensmith.jwt.jws.signer.factory.exception.InvalidJsonWebKeyException;
import net.tokensmith.jwt.jws.signer.factory.hmac.MacFactory;
import net.tokensmith.jwt.jws.signer.factory.rsa.PrivateKeySignatureFactory;
import net.tokensmith.jwt.jws.signer.factory.rsa.PublicKeySignatureFactory;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import net.tokensmith.jwt.jws.verifier.VerifySignature;
import net.tokensmith.jwt.jws.verifier.factory.VerifySignatureFactory;
import net.tokensmith.jwt.serialization.HeaderDeserializer;
import net.tokensmith.jwt.serialization.JwtSerde;
import net.tokensmith.jwt.serialization.Serdes;
import net.tokensmith.jwt.serialization.UnSecureJwtSerializer;
import net.tokensmith.jwt.jws.serialization.SecureJwtSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class JwtAppFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAppFactory.class);
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

    public PublicKeyTranslator publicKeyFactory() {
        return new PublicKeyTranslator(rsaKeyFactory());
    }

    public PublicKeySignatureFactory publicKeySignatureFactory() {
        return new PublicKeySignatureFactory(rsaKeyFactory());
    }

    public MacFactory macFactory() {
        return new MacFactory(urlDecoder());
    }

    public PrivateKeyTranslator privateKeyFactory() {
        return new PrivateKeyTranslator(rsaKeyFactory());
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
            jdkKey = publicKeyFactory().to(jwk);
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
