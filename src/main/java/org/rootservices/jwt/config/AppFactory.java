package org.rootservices.jwt.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.rootservices.jwt.translator.KeyPairToRSAKeyPair;
import org.rootservices.jwt.translator.PemToKeyPair;
import org.rootservices.jwt.builder.SecureJwtBuilder;
import org.rootservices.jwt.builder.UnsecureJwtBuilder;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
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
import org.rootservices.jwt.signature.verifier.VerifyRsaSignature;
import org.rootservices.jwt.signature.verifier.VerifySignature;
import org.rootservices.jwt.signature.verifier.VerifyMacSignature;
import org.rootservices.jwt.signature.signer.RSASigner;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.*;
import org.rootservices.jwt.signature.verifier.factory.VerifySignatureFactory;
import org.rootservices.jwt.signature.verifier.factory.VerifySignatureFactoryImpl;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URL;
import java.security.*;
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
        return new PublicKeySignatureFactoryImpl(urlDecoder());
    }

    public VerifyRsaSignature verifyRsaSignature(Algorithm algorithm, RSAPublicKey jwk) {
        Signature signature = publicKeySignatureFactory().makeSignature(algorithm, jwk);
        return new VerifyRsaSignature(signature, urlDecoder());
    }

    public MacFactory macFactory() {
        return new MacFactoryImpl();
    }

    public PrivateKeySignatureFactory privateKeySignatureFactory() {
        return new PrivateKeySignatureFactoryImpl(urlDecoder());
    }

    public SignerFactory signerFactory() {
        return new SignerFactoryImpl(
                macFactory(),
                privateKeySignatureFactory(),
                serializer(),
                encoder()
        );
    }

    public Signer RSASigner(Algorithm alg, RSAKeyPair jwk) {
        Signature signature = privateKeySignatureFactory().makeSignature(alg, jwk);
        return new RSASigner(signature, serializer(), encoder());
    }

    public VerifySignature verifyMacSignature(Algorithm algorithm, SymmetricKey key) {
        Signer macSigner = signerFactory().makeMacSigner(algorithm, key);
        return new VerifyMacSignature(macSigner);
    }

    public VerifySignatureFactory verifySignatureFactory() {
        return new VerifySignatureFactoryImpl(signerFactory(), publicKeySignatureFactory(), urlDecoder());
    }

    public UnsecureJwtBuilder unsecureJwtBuilder(){
        return new UnsecureJwtBuilder();
    }

    public SecureJwtBuilder secureJwtBuilder(Algorithm alg, Key jwk){
        Signer signer = signerFactory().makeSigner(alg, jwk);
        return new SecureJwtBuilder(signer);
    }

    public JcaPEMKeyConverter jcaPEMKeyConverter() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        return new JcaPEMKeyConverter().setProvider("BC");
    }

    public PEMParser pemParser(URL pemFileURL) {
        FileReader pemFileReader = null;
        try {
            pemFileReader = new FileReader(pemFileURL.getFile());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return new PEMParser(pemFileReader);
    }

    public PemToKeyPair pemToKeyPair(URL pemFileURL) {
        return new PemToKeyPair(pemParser(pemFileURL), jcaPEMKeyConverter());
    }

    public KeyPairToRSAKeyPair pemToRSAKeyPair() throws NoSuchAlgorithmException {
        return new KeyPairToRSAKeyPair(encoder(), KeyFactory.getInstance("RSA"));
    }
}
