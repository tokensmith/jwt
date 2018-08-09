package org.rootservices.jwt.builder.compact;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.rootservices.jwt.builder.exception.CompactException;
import org.rootservices.jwt.config.JwtAppFactory;
import org.rootservices.jwt.entity.jwe.EncryptionAlgorithm;
import org.rootservices.jwt.entity.jwk.RSAPublicKey;
import org.rootservices.jwt.entity.jwt.header.Algorithm;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.jwe.serialization.JweSerializer;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import org.rootservices.jwt.serialization.exception.EncryptException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;

import java.io.ByteArrayOutputStream;
import java.util.Optional;

public class EncryptedCompactBuilder {
    private static final Logger LOGGER = LogManager.getLogger(EncryptedCompactBuilder.class);
    public static final String UNABLE_TO_BUILD_COMPACT_JWE = "Unable to build compact jwe";
    private static JwtAppFactory jwtAppFactory = new JwtAppFactory();

    private byte[] payload;
    private byte[] cek;
    private Algorithm alg;
    private EncryptionAlgorithm encAlg;

    private RSAPublicKey publicKey;

    public EncryptedCompactBuilder payload(byte[] payload) {
        this.payload = payload;
        return this;
    }

    public EncryptedCompactBuilder rsa(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public EncryptedCompactBuilder cek(byte[] cek) {
        this.cek = cek;
        return this;
    }

    public EncryptedCompactBuilder alg(Algorithm alg) {
        this.alg = alg;
        return this;
    }

    public EncryptedCompactBuilder encAlg(EncryptionAlgorithm encAlg) {
        this.encAlg = encAlg;
        return this;
    }

    public ByteArrayOutputStream build() throws CompactException {
        JWE jwe = jwe();
        JweSerializer jweSerializer = jweSerializer();

        try {
            return jweSerializer.JWEToCompact(jwe);
        } catch (JsonToJwtException | CipherException | EncryptException e) {
            LOGGER.error(e.getMessage(), e);
            throw new CompactException(UNABLE_TO_BUILD_COMPACT_JWE, e);
        }
    }

    // a few factory methods to help the build method.

    protected JweSerializer jweSerializer() throws CompactException {
        JweSerializer jweSerializer;
        if (publicKey != null) {
            jweSerializer = jweRsaSerializer();
        } else {
            jweSerializer = jwtAppFactory.jweDirectSerializer();
        }
        return jweSerializer;
    }

    protected JweSerializer jweRsaSerializer() throws CompactException {
        try {
            return jwtAppFactory.jweRsaSerializer(publicKey);
        } catch (PublicKeyException | CipherException e) {
            LOGGER.error(e.getMessage(), e);
            throw new CompactException(UNABLE_TO_BUILD_COMPACT_JWE, e);
        }
    }

    protected JWE jwe() {
        if (publicKey != null) {
            return jweForRsa();
        } else {
            return jweForDirect();
        }
    }

    protected JWE jweForDirect() {
        JWE jwe = new JWE();
        Header header = new Header();

        header.setEncryptionAlgorithm(Optional.of(this.encAlg));
        header.setAlgorithm(this.alg);

        jwe.setHeader(header);
        jwe.setPayload(payload);
        jwe.setCek(cek);

        return jwe;
    }

    protected JWE jweForRsa() {
        JWE jwe = new JWE();
        Header header = new Header();

        header.setKeyId(publicKey.getKeyId());
        header.setEncryptionAlgorithm(Optional.of(this.encAlg));
        header.setAlgorithm(this.alg);

        jwe.setHeader(header);
        jwe.setPayload(payload);

        return jwe;
    }
}
