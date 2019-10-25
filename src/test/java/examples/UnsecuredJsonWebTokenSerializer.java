package examples;

import helper.entity.Claim;
import net.tokensmith.jwt.builder.compact.UnsecureCompactBuilder;

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
