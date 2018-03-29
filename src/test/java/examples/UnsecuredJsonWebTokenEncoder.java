package examples;

import helper.entity.Claim;
import org.rootservices.jwt.serialization.UnSecureJwtSerializer;
import org.rootservices.jwt.config.JwtAppFactory;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class UnsecuredJsonWebTokenEncoder {

    public String toEncodedJwt() {
        JwtAppFactory appFactory = new JwtAppFactory();
        UnSecureJwtSerializer unSecureJwtSerializer = appFactory.unSecureJwtSerializer();

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        String encodedJwt = unSecureJwtSerializer.encode(claim);

        return encodedJwt;
    }
}
