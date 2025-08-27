package com.mycompany.cryptoserver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyLoader {

    // ✅ Load PrivateKey từ InputStream (dùng cho server.key)
    public static PrivateKey loadPrivateKey(InputStream in) throws Exception {
        String pem = readPEM(in, "PRIVATE KEY");
        byte[] keyBytes = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    // ✅ Load PublicKey từ PEM định dạng (client gửi)
    public static PublicKey loadPublicKey(byte[] pemBytes) throws Exception {
        String pem = new String(pemBytes);
        String cleaned = pem.replaceAll("-----BEGIN (.*?)-----", "")
                            .replaceAll("-----END (.*?)-----", "")
                            .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    // ✅ Load PublicKey từ file PEM (nếu cần dùng lại cách cũ)
    public static PublicKey loadPublicKey(InputStream in) throws Exception {
        String pem = readPEM(in, "PUBLIC KEY");
        byte[] keyBytes = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    // ✅ Load PublicKey từ chứng chỉ (server.crt)
    public static PublicKey loadPublicKeyFromCert(InputStream certInputStream) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cert = cf.generateCertificate(certInputStream);
        return cert.getPublicKey();
    }

    // ✅ Đọc nội dung PEM từ InputStream
    private static String readPEM(InputStream in, String type) throws IOException {
        StringBuilder sb = new StringBuilder();
        boolean inKey = false;

        try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.contains("BEGIN " + type)) {
                    inKey = true;
                } else if (line.contains("END " + type)) {
                    break;
                } else if (inKey) {
                    sb.append(line);
                }
            }
        }

        return sb.toString();
    }
}
