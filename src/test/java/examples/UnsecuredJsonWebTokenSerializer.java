package examples;

import helper.entity.Claim;
import org.rootservices.jwt.builder.compact.UnsecureCompactBuilder;
import org.rootservices.jwt.serialization.UnSecureJwtSerializer;
import org.rootservices.jwt.config.JwtAppFactory;

import java.io.ByteArrayOutputStream;


public class UnsecuredJsonWebTokenSerializer {

    public String toEncodedJwt() {

        UnsecureCompactBuilder compactBuilder = new UnsecureCompactBuilder();

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        ByteArrayOutputStream encodedJwt = compactBuilder.claims(claim).build();

        return encodedJwt.toString();
    }
}
