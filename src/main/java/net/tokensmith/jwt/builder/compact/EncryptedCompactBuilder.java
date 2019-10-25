package net.tokensmith.jwt.builder.compact;

import net.tokensmith.jwt.entity.jwe.EncryptionAlgorithm;
import net.tokensmith.jwt.entity.jwk.RSAPublicKey;
import net.tokensmith.jwt.entity.jwk.SymmetricKey;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.Header;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import net.tokensmith.jwt.builder.exception.CompactException;
import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.jwe.entity.JWE;
import net.tokensmith.jwt.jwe.factory.exception.CipherException;
import net.tokensmith.jwt.jwe.serialization.JweSerializer;
import net.tokensmith.jwt.jws.signer.factory.rsa.exception.PublicKeyException;
import net.tokensmith.jwt.serialization.exception.EncryptException;
import net.tokensmith.jwt.serialization.exception.JsonToJwtException;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.Optional;

public class EncryptedCompactBuilder {
    private static final Logger LOGGER = LogManager.getLogger(EncryptedCompactBuilder.class);
    public static final String UNABLE_TO_BUILD_COMPACT_JWE = "Unable to build compact jwe";
    private static JwtAppFactory jwtAppFactory = new JwtAppFactory();

    private byte[] payload;
    private SymmetricKey cek;
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

    public EncryptedCompactBuilder cek(SymmetricKey cek) {
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
        Base64.Decoder decoder = jwtAppFactory.urlDecoder();

        JWE jwe = new JWE();
        Header header = new Header();

        header.setEncryptionAlgorithm(Optional.of(this.encAlg));
        header.setAlgorithm(this.alg);
        header.setKeyId(cek.getKeyId());

        jwe.setHeader(header);
        jwe.setPayload(payload);
        jwe.setCek(decoder.decode(cek.getKey()));

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
