package com.mycompany.crypto;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import com.fasterxml.jackson.databind.ObjectMapper;

public class SecureMessageBuilder {

    public String buildSecurePayload(String rawMessage, File privateKeyFile, File serverPublicKeyFile, File clientPublicKeyFile) throws Exception {
        // ✅ Load client private key để ký
        PrivateKey privateKey = KeyLoader.loadPrivateKey(privateKeyFile);

        // ✅ Load server public key từ PEM
        String serverPubPem = Files.readString(serverPublicKeyFile.toPath());
        String serverPubCleaned = serverPubPem
                .replaceAll("-----BEGIN (.*?)-----", "")
                .replaceAll("-----END (.*?)-----", "")
                .replaceAll("\\s", "");
        byte[] derEncoded = Base64.getDecoder().decode(serverPubCleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(derEncoded);
        PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(spec);

        // ✅ Ký message bằng SHA256withRSA
        byte[] signatureBytes = CryptoUtil.signSHA256WithRSA(rawMessage.getBytes(), privateKey);
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

        // ✅ Sinh AES key và IV
        SecretKey aesKey = CryptoUtil.generateAESKey(256);
        byte[] aesIV = CryptoUtil.generateIV(16);

        // ✅ Mã hóa message bằng AES
        byte[] encryptedMessage = CryptoUtil.encryptAES(rawMessage.getBytes(), aesKey, aesIV);
        String encryptedMessageBase64 = Base64.getEncoder().encodeToString(encryptedMessage);

        // ✅ Load và mã hóa client public key bằng AES
        String clientPubPem = Files.readString(clientPublicKeyFile.toPath());
        String clientPubCleaned = clientPubPem
                .replaceAll("-----BEGIN (.*?)-----", "")
                .replaceAll("-----END (.*?)-----", "")
                .replaceAll("\\s", "");
        byte[] decodedClientPub = Base64.getDecoder().decode(clientPubCleaned);
        byte[] encryptedPubKeyBytes = CryptoUtil.encryptAES(decodedClientPub, aesKey, aesIV);
        String encryptedPubKeyBase64 = Base64.getEncoder().encodeToString(encryptedPubKeyBytes);

        // ✅ Mã hóa AES key và IV bằng RSA (server public key)
        byte[] encryptedAESKey = CryptoUtil.encryptRSA(aesKey.getEncoded(), serverPublicKey);
        byte[] encryptedAESIV = CryptoUtil.encryptRSA(aesIV, serverPublicKey);

        // ✅ Tạo JSON payload
        Map<String, String> payload = new HashMap<>();
        payload.put("encryptedMessage", encryptedMessageBase64);
        payload.put("signature", signatureBase64);
        payload.put("encryptedPubKey", encryptedPubKeyBase64);
        payload.put("aesKey", Base64.getEncoder().encodeToString(encryptedAESKey));
        payload.put("aesIV", Base64.getEncoder().encodeToString(encryptedAESIV));

        return new ObjectMapper().writeValueAsString(payload);
    }
}
