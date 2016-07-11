package examples;

import helper.entity.Claim;
import org.rootservices.jwt.factory.SecureJwtFactory;
import org.rootservices.jwt.config.AppFactory;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwk.Use;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.serializer.JWTSerializer;
import org.rootservices.jwt.serializer.exception.JsonToJwtException;
import org.rootservices.jwt.serializer.exception.JwtToJsonException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidAlgorithmException;
import org.rootservices.jwt.signature.signer.factory.exception.InvalidJsonWebKeyException;
import org.rootservices.jwt.signature.verifier.VerifySignature;

import java.util.Optional;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class SymmetricSignedJsonWebToken {

    public String toJson() throws JwtToJsonException, InvalidJsonWebKeyException, InvalidAlgorithmException {

        AppFactory appFactory = new AppFactory();

        SymmetricKey key = new SymmetricKey(
                Optional.of("test-key-id"),
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
                Use.SIGNATURE
        );

        SecureJwtFactory secureJwtFactory = null;
        try {
            secureJwtFactory = appFactory.secureJwtBuilder(Algorithm.HS256, key);
        } catch (InvalidJsonWebKeyException e) {
            throw e;
        } catch (InvalidAlgorithmException e) {
            throw e;
        }

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        JsonWebToken jsonWebToken = null;
        try {
            jsonWebToken = secureJwtFactory.makeJwt(claim);
        } catch (JwtToJsonException e) {
            // could not create JsonWebToken, e.cause will provide details
            throw e;
        }

        JWTSerializer jwtSerializer = appFactory.jwtSerializer();

        String jwt = null;
        try {
            jwt = jwtSerializer.jwtToString(jsonWebToken);
        } catch (JwtToJsonException e) {
            // could not serialize JsonWebToken to json
            throw e;
        }

        return jwt;
    }

    public Boolean verifySignature() throws JsonToJwtException, InvalidJsonWebKeyException, InvalidAlgorithmException {

        AppFactory appFactory = new AppFactory();

        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.TeZ3DKSE-gplbaoA8CK_RMojt8CfA1MTYaM_ZuOeGNw";
        JWTSerializer jwtSerializer = appFactory.jwtSerializer();

        JsonWebToken jsonWebToken = null;
        try {
            jsonWebToken = jwtSerializer.stringToJwt(jwt, Claim.class);
        } catch (JsonToJwtException e) {
            // could not create a JsonWebToken from the jwt json.
            throw e;
        }

        SymmetricKey key = new SymmetricKey(
                Optional.of("test-key-id"),
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
                Use.SIGNATURE
        );


        VerifySignature verifySignature = null;
        try {
            verifySignature = appFactory.verifySignature(Algorithm.HS256, key);
        } catch (InvalidJsonWebKeyException e) {
            throw e;
        } catch (InvalidAlgorithmException e) {
            throw e;
        }

        return verifySignature.run(jsonWebToken);
    }

}
