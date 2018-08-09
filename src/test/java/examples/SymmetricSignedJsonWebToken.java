package examples;

import helper.entity.Claim;
import org.rootservices.jwt.builder.compact.SecureCompactBuilder;
import org.rootservices.jwt.builder.exception.CompactException;
import org.rootservices.jwt.jws.serialization.SecureJwtSerializer;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwk.SymmetricKey;
import org.rootservices.jwt.entity.jwk.Use;
import org.rootservices.jwt.entity.jwt.JsonWebToken;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.exception.SignatureException;
import org.rootservices.jwt.serialization.JwtSerde;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;
import org.rootservices.jwt.serialization.exception.JwtToJsonException;
import org.rootservices.jwt.jws.verifier.VerifySignature;

import java.io.ByteArrayOutputStream;
import java.util.Optional;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class SymmetricSignedJsonWebToken {

    public String tocCompactJwt() {

        SecureCompactBuilder compactBuilder = new SecureCompactBuilder();

        SymmetricKey key = new SymmetricKey(
                Optional.of("test-key-id"),
                "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
                Use.SIGNATURE
        );

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        ByteArrayOutputStream encodedJwt = null;
        try {
            encodedJwt = compactBuilder.claims(claim)
                    .key(key)
                    .alg(Algorithm.HS256)
                    .build();
        } catch (CompactException e) {
            e.printStackTrace();
        }

        return encodedJwt.toString();
    }

    public Boolean verifySignature() throws Exception {

        JwtAppFactory appFactory = new JwtAppFactory();

        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.TeZ3DKSE-gplbaoA8CK_RMojt8CfA1MTYaM_ZuOeGNw";
        JwtSerde jwtSerde = appFactory.jwtSerde();

        JsonWebToken jsonWebToken = null;
        try {
            jsonWebToken = jwtSerde.stringToJwt(jwt, Claim.class);
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
        } catch (SignatureException e) {
            throw e;
        }

        return verifySignature.run(jsonWebToken);
    }

}
