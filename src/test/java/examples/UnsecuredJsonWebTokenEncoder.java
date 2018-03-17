package examples;

import helper.entity.Claim;
import org.rootservices.jwt.UnSecureJwtEncoder;
import org.rootservices.jwt.config.JwtAppFactory;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class UnsecuredJsonWebTokenEncoder {

    public String toEncodedJwt() {
        JwtAppFactory appFactory = new JwtAppFactory();
        UnSecureJwtEncoder unSecureJwtEncoder = appFactory.unSecureJwtEncoder();

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        String encodedJwt = unSecureJwtEncoder.encode(claim);

        return encodedJwt;
    }
}
