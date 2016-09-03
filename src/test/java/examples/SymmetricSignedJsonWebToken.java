package examples;

import helper.entity.Claim;
import org.rootservices.jwt.SecureJwtEncoder;
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

    public String toEncodedJwt() {

        AppFactory appFactory = new AppFactory();

        SymmetricKey key = new SymmetricKey(
                Optional.of("test-key-id"),
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
                Use.SIGNATURE
        );

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        SecureJwtEncoder secureJwtEncoder = null;
        try {
            secureJwtEncoder = appFactory.secureJwtEncoder(Algorithm.HS256, key);
        } catch (InvalidAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidJsonWebKeyException e) {
            e.printStackTrace();
        }

        String encodedJwt = null;
        try {
            encodedJwt = secureJwtEncoder.encode(claim);
        } catch (JwtToJsonException e) {
            e.printStackTrace();
        }

        return encodedJwt;
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
