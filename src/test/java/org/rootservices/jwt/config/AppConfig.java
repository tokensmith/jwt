package org.rootservices.jwt.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import org.rootservices.jwt.builder.TokenBuilder;
import org.rootservices.jwt.marshaller.TokenMarshaller;
import org.rootservices.jwt.marshaller.TokenMarshallerImpl;
import org.rootservices.jwt.serializer.Serializer;
import org.rootservices.jwt.serializer.SerializerImpl;

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

    public TokenMarshaller tokenMarshaller() {
        return new TokenMarshallerImpl(serializer(), Base64.getEncoder(), Base64.getDecoder());
    }
}
