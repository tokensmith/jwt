package examples;

import helper.entity.Claim;
import org.rootservices.jwt.serialization.UnSecureJwtSerializer;
import org.rootservices.jwt.config.JwtAppFactory;


public class UnsecuredJsonWebTokenSerializer {

    public String toEncodedJwt() {
        JwtAppFactory appFactory = new JwtAppFactory();
        UnSecureJwtSerializer unSecureJwtSerializer = appFactory.unSecureJwtSerializer();

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        String encodedJwt = unSecureJwtSerializer.compactJwtToString(claim);

        return encodedJwt;
    }
}
