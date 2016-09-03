package examples;

import helper.entity.Claim;
import org.rootservices.jwt.UnSecureJwtEncoder;
import org.rootservices.jwt.factory.UnSecureJwtFactory;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class UnsecuredJsonWebTokenEncoder {

    public String toEncodedJwt() {
        AppFactory appFactory = new AppFactory();
        UnSecureJwtEncoder unSecureJwtEncoder = appFactory.unSecureJwtEncoder();

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        String encodedJwt = unSecureJwtEncoder.encode(claim);

        return encodedJwt;
    }
}
