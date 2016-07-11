package examples;

import helper.entity.Claim;
import org.rootservices.jwt.factory.UnsecureJwtFactory;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class UnsecuredJsonWebToken {

    public String toJson() throws JwtToJsonException {
        AppFactory appFactory = new AppFactory();
        UnsecureJwtFactory unsecureTokenBuilder = appFactory.unsecureJwtBuilder();

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        JsonWebToken jsonWebToken = unsecureTokenBuilder.makeJwt(claim);

        JWTSerializer jwtSerializer = appFactory.jwtSerializer();

        String jwt = null;
        try {
            jwt = jwtSerializer.jwtToString(jsonWebToken);
        } catch (JwtToJsonException e) {
            throw e;
        }

        return jwt;
    }
}
