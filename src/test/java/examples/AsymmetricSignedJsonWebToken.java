package examples;

import helper.entity.Claim;
import net.tokensmith.jwt.builder.compact.SecureCompactBuilder;
import net.tokensmith.jwt.builder.exception.CompactException;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.entity.jwk.RSAKeyPair;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
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
import java.math.BigInteger;
import java.util.Optional;

/**
 * Created by tommackenzie on 12/12/15.
 */
public class AsymmetricSignedJsonWebToken {

    public ByteArrayOutputStream toCompactJwt() throws KeyGenerateException {

        SecureCompactBuilder compactBuilder = new SecureCompactBuilder();

        JwtAppFactory jwtAppFactory = new JwtAppFactory();
        KeyGenerator keyGenerator = jwtAppFactory.keyGenerator();

        RSAKeyPair keyPair;
        try {
            keyPair= keyGenerator.rsaKeyPair(
                KeyGenerator.RSA_1024,
                Optional.of("test-key-id"),
                Use.SIGNATURE
            );
        } catch (KeyGenerateException e) {
            throw e;
        }

        Claim claim = new Claim();
        claim.setUriIsRoot(true);

        ByteArrayOutputStream encodedJwt = null;
        try {
            encodedJwt = compactBuilder.claims(claim)
                    .key(keyPair)
                    .alg(Algorithm.RS256)
                    .build();
        } catch (CompactException e) {
            e.printStackTrace();
        }

        return encodedJwt;
    }

    public Boolean verifySignature() throws Exception {
        String jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0.ZaZoTp-lb3C7Sb7BKQm3BZyGiMxtehBtAeN9anuDPgO_F3eR8o9UU4c1RgCFDLqO_Ftg6QCmoZ1SEDuNw8AskJWSqcuJwcOttrqf46BHB89QuGtfmhEb5fIbyuqD-n2XM2hHhvPL6yJvLd3VQNvW2VexSL3fmutC5MYoPa8IfvjGZ_QKMwA7BBwcm4Djnnlu9HwiNg3a_y6-JJxr_jW5GD8VomHZbLasokR6h5N-y-DXIIYL3-oMl-_rE1BPdm_gE76p4Lo49BM-AyUxbShAHDl-EBKsz_Vo-Pgk_4rXkBOMMJQI95FrK5FeJs2yZxMoZ_V_f5_VGnXYNzq3SFJwnQ";

        RSAPublicKey publicKey = new RSAPublicKey(
                Optional.of("test-key-id"),
                Use.SIGNATURE,
                new BigInteger("20446702916744654562596343388758805860065209639960173505037453331270270518732245089773723012043203236097095623402044690115755377345254696448759605707788965848889501746836211206270643833663949992536246985362693736387185145424787922241585721992924045675229348655595626434390043002821512765630397723028023792577935108185822753692574221566930937805031155820097146819964920270008811327036286786392793593121762425048860211859763441770446703722015857250621107855398693133264081150697423188751482418465308470313958250757758547155699749157985955379381294962058862159085915015369381046959790476428631998204940879604226680285601"),
                new BigInteger("65537")
        );

        JwtAppFactory appFactory = new JwtAppFactory();
        JwtSerde jwtSerde = appFactory.jwtSerde();
        JsonWebToken<Claim> jsonWebToken;
        try {
            jsonWebToken = jwtSerde.stringToJwt(jwt, Claim.class);
        } catch (JsonToJwtException e) {
            // could not serialize JsonWebToken to json string
            throw e;
        }


        VerifySignature verifySignature;
        try {
            verifySignature = appFactory.verifySignature(Algorithm.RS256, publicKey);
        } catch (SignatureException e) {
            throw e;
        }

        return verifySignature.run(jsonWebToken);
    }
}
