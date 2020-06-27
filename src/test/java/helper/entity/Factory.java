package helper.entity;

import net.tokensmith.jwt.config.JwtAppFactory;
import net.tokensmith.jwt.entity.jwk.*;
import net.tokensmith.jwt.entity.jwt.JsonWebToken;
import net.tokensmith.jwt.entity.jwt.header.Algorithm;
import net.tokensmith.jwt.entity.jwt.header.Header;
import net.tokensmith.jwt.entity.jwt.header.TokenType;

import java.math.BigInteger;
import java.util.Base64;
import java.util.Optional;

/**
 * Created by tommackenzie on 11/12/15.
 */
public class Factory {
    private static JwtAppFactory APP_FACTORY = new JwtAppFactory();

    public static BigInteger toBigInt(String value) {
        byte[] decodedBytes = Base64.getUrlDecoder().decode(value);
        return new BigInteger(1, decodedBytes);
    }
    /*
     * This RSA key pair comes from, https://tools.ietf.org/html/rfc7515#appendix-A.2
     */
    public static RSAKeyPair makeRSAKeyPair() {
        return new RSAKeyPair(
                Optional.<String>empty(),
                Use.SIGNATURE,
                toBigInt("ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"),
                toBigInt("AQAB"),
                toBigInt("Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"),
                toBigInt("4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"),
                toBigInt("uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"),
                toBigInt("BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"),
                toBigInt("h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"),
                toBigInt("IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U")
        );
    }

    public static RSAPublicKey makeRSAPublicKey() {
        return new RSAPublicKey(
                Optional.<String>empty(),
                Use.SIGNATURE,
                toBigInt("ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"),
                toBigInt("AQAB")
        );
    }

    public static SymmetricKey makeSymmetricKey() throws Exception{
        SymmetricKey key = new SymmetricKey(
            Optional.<String>empty(),
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
            Use.SIGNATURE
        );

        return key;
    }

    public static SymmetricKey makeBadSymmetricKey() {

        return new SymmetricKey(
                Optional.<String>empty(),
                "%%%%^&&*(#*$(#*$#@(*$E*E(",
                Use.SIGNATURE
        );
    }

    public static SymmetricKey makeSymmetricKeyForJWE() {
        SymmetricKey key = new SymmetricKey(
                Optional.<String>empty(),
                "MMNj8rE5m7NIDhwKYDmHSnlU1wfKuVvW6G--GKPYkRA",
                Use.ENCRYPTION
        );

        return key;
    }

    public static Claim makeClaim() {
        Claim claim = new Claim();
        Optional<String> issuer = Optional.of("joe");
        Optional<Long> expirationTime = Optional.of(1300819380L);
        claim.setUriIsRoot(true);
        claim.setIssuer(issuer);
        claim.setExpirationTime(expirationTime);

        return claim;
    }

    public static JsonWebToken<Claim> makeToken(Algorithm algorithm, Optional<TokenType> tokenType) {

        // header
        Header header = new Header();
        header.setAlgorithm(algorithm);
        header.setType(tokenType);

        // claim of the token.
        Claim claim = makeClaim();

        return new JsonWebToken<>(header, claim);
    }

    public static byte[] aad() {
        byte[] aad = "aad".getBytes();
        return aad;
    }

    // taken from, https://tools.ietf.org/html/rfc7515#appendix-A.1
    public static RSAKeyPair makeRSAKeyPairForJWE() {


        StringBuilder n = new StringBuilder();
        n.append("oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW");
        n.append("cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S");
        n.append("psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a");
        n.append("sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS");
        n.append("tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj");
        n.append("YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw");

        StringBuilder e = new StringBuilder();
        e.append("AQAB");

        StringBuilder d = new StringBuilder();
        d.append("kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5N");
        d.append("WV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD9");
        d.append("3Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghk");
        d.append("qDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vl");
        d.append("t3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSnd");
        d.append("VTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ");

        StringBuilder p = new StringBuilder();
        p.append("1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-");
        p.append("SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lf");
        p.append("fNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0");

        StringBuilder q = new StringBuilder();
        q.append("wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBm");
        q.append("UDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aX");
        q.append("IWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc");

        StringBuilder dp = new StringBuilder();
        dp.append("ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KL");
        dp.append("hMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827");
        dp.append("rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE");

        StringBuilder dq = new StringBuilder();
        dq.append("Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCj");
        dq.append("ywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDB");
        dq.append("UfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis");

        StringBuilder qi = new StringBuilder();
        qi.append("VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7");
        qi.append("AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3");
        qi.append("eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY");

        return new RSAKeyPair(
                Optional.<String>empty(),
                Use.ENCRYPTION,
                toBigInt(n.toString()),
                toBigInt(e.toString()),
                toBigInt(d.toString()),
                toBigInt(p.toString()),
                toBigInt(q.toString()),
                toBigInt(dp.toString()),
                toBigInt(dq.toString()),
                toBigInt(qi.toString())
        );
    }

    public static RSAPublicKey makeRSAPublicKeyForJWE() {
        StringBuilder n = new StringBuilder();
        n.append("oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW");
        n.append("cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S");
        n.append("psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a");
        n.append("sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS");
        n.append("tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj");
        n.append("YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw");

        StringBuilder e = new StringBuilder();
        e.append("AQAB");

        return new RSAPublicKey(
                Optional.<String>empty(),
                Use.ENCRYPTION,
                toBigInt(n.toString()),
                toBigInt(e.toString())
        );

    }

    // taken from, https://tools.ietf.org/html/rfc7516#section-3.3
    public static String compactJWE() {
        StringBuilder encoded = new StringBuilder();
        encoded.append("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.");
        encoded.append("OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe");
        encoded.append("ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb");
        encoded.append("Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV");
        encoded.append("mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8");
        encoded.append("1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi");
        encoded.append("6UklfCpIMfIjf7iGdXKHzg.");
        encoded.append("48V1_ALb6US04U3b.");
        encoded.append("5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji");
        encoded.append("SdiwkIr3ajwQzaBtQD_A.");
        encoded.append("XFBoMYUZodetZdvTiFvSkQ");

        return encoded.toString();
    }

    public static String symmetricCompactJWE() {
        return "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..0gDRrNTkCcMW_nnA1Q1yKUi0kJEAFxblm2-oUG0QhxEVtbzhWAlUnS5azsiC24Zk7Vv6DYOGCBkt2WSt_Yp2BYWrSHyxWVhNnQ0qtvm2TTh2MHjonN2Kb1NH_ooRLs6Z.NgpZSFNCr7s3SuA4mgoU1jY3bUi5KCp1pZwJ4VZT9yM8qduQaOAZj7qGRbxh.vSdENsFN2CpC1AunaZFJ-w";
    }
}
