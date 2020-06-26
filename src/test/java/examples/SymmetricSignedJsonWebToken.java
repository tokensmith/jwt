package examples;

import helper.entity.Claim;
import net.tokensmith.jwt.builder.compact.SecureCompactBuilder;
import net.tokensmith.jwt.builder.exception.CompactException;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwk.Use;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.exception.SignatureException;
import net.tokensmith.jwt.jwk.generator.KeyGenerator;
import net.tokensmith.jwt.jwk.generator.exception.KeyGenerateException;
import net.tokensmith.jwt.serialization.JwtSerde;
import net.tokensmith.jwt.serialization.exception.JsonToJwtException;
import net.tokensmith.jwt.jws.verifier.VerifySignature;

import java.io.ByteArrayOutputStream;
import java.util.Optional;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class SymmetricSignedJsonWebToken {

    public ByteArrayOutputStream toCompactJwt() throws KeyGenerateException {

        SecureCompactBuilder compactBuilder = new SecureCompactBuilder();

        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        KeyGenerator keyGenerator = jwtAppFactory.keyGenerator();

        SymmetricKey key;

        try {
            key = keyGenerator.symmetricKey(Optional.of("test-key-id"), Use.SIGNATURE);
        } catch (KeyGenerateException e) {
            throw e;
        }

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

        return encodedJwt;
    }

    public Boolean verifySignature() throws Exception {

        JwtAppFactory appFactory = new JwtAppFactory();

        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.TeZ3DKSE-gplbaoA8CK_RMojt8CfA1MTYaM_ZuOeGNw";
        JwtSerde jwtSerde = appFactory.jwtSerde();

        JsonWebToken<Claim> jsonWebToken;
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
