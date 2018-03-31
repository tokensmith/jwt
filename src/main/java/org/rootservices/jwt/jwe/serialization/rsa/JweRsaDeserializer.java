package org.rootservices.jwt.jwe.serialization.rsa;

import org.rootservices.jwt.entity.jwk.Key;
import org.rootservices.jwt.entity.jwk.RSAKeyPair;
import org.rootservices.jwt.jwe.Transformation;
import org.rootservices.jwt.jwe.entity.JWE;
import org.rootservices.jwt.jwe.factory.CipherRSAFactory;
import org.rootservices.jwt.jwe.factory.CipherSymmetricFactory;
import org.rootservices.jwt.jwe.factory.exception.CipherException;
import org.rootservices.jwt.entity.jwt.header.Header;
import org.rootservices.jwt.jwe.serialization.JweDeserializer;
import org.rootservices.jwt.jwe.serialization.exception.KeyException;
import org.rootservices.jwt.jwk.PrivateKeyFactory;
import org.rootservices.jwt.jws.signer.factory.rsa.exception.PrivateKeyException;
import org.rootservices.jwt.serialization.Serializer;
import org.rootservices.jwt.serialization.exception.DecryptException;
import org.rootservices.jwt.serialization.exception.JsonException;
import org.rootservices.jwt.serialization.exception.JsonToJwtException;


import javax.crypto.*;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;

public class JweRsaDeserializer implements JweDeserializer {

    private Serializer serializer;
    private Base64.Decoder decoder;
    private PrivateKeyFactory privateKeyFactory;
    private CipherRSAFactory cipherRSAFactory;
    private CipherSymmetricFactory cipherSymmetricFactory;

    public JweRsaDeserializer(Serializer serializer, Base64.Decoder decoder, PrivateKeyFactory privateKeyFactory, CipherRSAFactory cipherRSAFactory, CipherSymmetricFactory cipherSymmetricFactory) {
        this.serializer = serializer;
        this.decoder = decoder;
        this.privateKeyFactory = privateKeyFactory;
        this.cipherRSAFactory = cipherRSAFactory;
        this.cipherSymmetricFactory = cipherSymmetricFactory;
    }

    public JWE stringToJWE(String compactJWE, Key key) throws JsonToJwtException, DecryptException, CipherException, KeyException {
        String[] jweParts = compactJWE.split(JWT_SPLITTER);
        byte[] protectedHeader = decoder.decode(jweParts[0]);
        byte[] encryptedKey = decoder.decode(jweParts[1]);
        byte[] initVector = decoder.decode(jweParts[2]);
        byte[] cipherText = decoder.decode(jweParts[3]);
        byte[] authenticationTag = decoder.decode(jweParts[4]);

        Header header;
        try {
            header = (Header) serializer.jsonBytesToObject(protectedHeader, Header.class);
        } catch (JsonException e) {
            throw new JsonToJwtException(COMPACT_JWE_INVALID, e);
        }

        RSAKeyPair keyPair = (RSAKeyPair) key;
        RSAPrivateCrtKey jdkKey;
        try {
            jdkKey = privateKeyFactory.makePrivateKey(keyPair);
        } catch (PrivateKeyException e) {
            throw new KeyException("", e);
        }

        Cipher rsaDecryptCipher;
        try {
            rsaDecryptCipher = cipherRSAFactory.forDecrypt(Transformation.RSA_OAEP, jdkKey);
        } catch (CipherException e) {
            throw e;
        }

        byte[] cek;
        try {
            cek = rsaDecryptCipher.doFinal(encryptedKey);
        } catch (IllegalBlockSizeException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_ENCRYPTED_KEY, e);
        } catch (BadPaddingException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_ENCRYPTED_KEY, e);
        }

        byte[] aad = jweParts[0].getBytes(StandardCharsets.US_ASCII);

        Cipher symmetricCipher;
        try {
            symmetricCipher = cipherSymmetricFactory.forDecrypt(Transformation.AES_GCM_NO_PADDING, cek, initVector, aad);
        } catch (CipherException e) {
            throw e;
        }

        byte[] cipherTextWithAuthTag = cipherTextWithAuthTag(cipherText, authenticationTag);

        byte[] payload;
        try {
            payload = symmetricCipher.doFinal(cipherTextWithAuthTag);
        } catch (IllegalBlockSizeException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_CIPHER_TEXT, e);
        } catch (BadPaddingException e) {
            throw new DecryptException(COULD_NOT_DECRYPT_CIPHER_TEXT, e);
        }

        return new JWE(header, payload, cek, initVector, authenticationTag);
    }
}
