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
import org.rootservices.jwt.signer.MacSignerImpl;
import org.rootservices.jwt.signer.Signer;
import org.rootservices.jwt.signer.factory.KeyFactory;
import org.rootservices.jwt.signer.factory.KeyFactoryImpl;
import org.rootservices.jwt.signer.factory.SignerFactory;
import org.rootservices.jwt.signer.factory.SignerFactoryImpl;

import java.util.Base64;

/**
 * Created by tommackenzie on 8/13/15.
 */
public class AppConfig {

    public TokenBuilder tokenBuilder(){
        return new TokenBuilder();
    }

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

    public JWTSerializer jwtSerializer() {
        return new JWTSerializerImpl(serializer(), Base64.getEncoder(), Base64.getDecoder());
    }

    public KeyFactory keyFactory() {
        return new KeyFactoryImpl();
    }

    public SignerFactory signerFactory() {
        return new SignerFactoryImpl(keyFactory());
    }
}
