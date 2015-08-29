package org.rootservices.jwt.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.rootservices.jwt.builder.TokenBuilder;
import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.JWTSerializerImpl;
import org.rootservices.jwt.serializer.Serializer;
import org.rootservices.jwt.serializer.SerializerImpl;
import org.rootservices.jwt.signature.signer.MacSignerImpl;
import org.rootservices.jwt.signature.signer.Signer;
import org.rootservices.jwt.signature.signer.factory.KeyFactory;
import org.rootservices.jwt.signature.signer.factory.KeyFactoryImpl;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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

    public Base64.Encoder encoder() {
        return Base64.getUrlEncoder().withoutPadding();
    }

    public Base64.Decoder decoder() {
        return Base64.getDecoder();
    }

    public JWTSerializer jwtSerializer() {
        return new JWTSerializerImpl(serializer(), encoder(), decoder());
    }

    public KeyFactory keyFactory() {
        return new KeyFactoryImpl();
    }

    public Mac mac(java.security.Key securityKey) {
        Mac mac = null;
        try {
            mac = Mac.getInstance(securityKey.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            mac.init(securityKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return mac;
    }

    public Signer signer(Algorithm alg, Key jwk) {
        java.security.Key securitykey = keyFactory().makeKey(alg, jwk);
        Mac mac = mac(securitykey);
        return new MacSignerImpl(
                serializer(),
                mac,
                encoder()
        );
    }

    public TokenBuilder tokenBuilder(Algorithm alg, Key jwk){
        return new TokenBuilder(jwtSerializer(), signer(alg, jwk));
    }
}
