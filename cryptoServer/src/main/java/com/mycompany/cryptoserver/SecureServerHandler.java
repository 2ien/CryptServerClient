package com.mycompany.cryptoserver;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

public class SecureServerHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private final ObjectMapper mapper = new ObjectMapper();
    private final PrivateKey serverPrivateKey;
    private final PublicKey serverPublicKey;

    public SecureServerHandler() throws Exception {
        InputStream keyStream = getClass().getClassLoader().getResourceAsStream("keys/server.key");
        if (keyStream == null) throw new IllegalStateException("Không tìm thấy file server.key trong resources.");
        serverPrivateKey = KeyLoader.loadPrivateKey(keyStream);

        InputStream certStream = getClass().getClassLoader().getResourceAsStream("keys/server.crt");
        if (certStream == null) throw new IllegalStateException("Không tìm thấy file server.crt trong resources.");
        serverPublicKey = KeyLoader.loadPublicKeyFromCert(certStream);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
        String received = msg.toString(StandardCharsets.UTF_8).trim();
        System.out.println("📩 Nhận từ client: " + received);
        // Xử lý lệnh STOP_SCAN từ client
        if (received.equalsIgnoreCase("STOP_SCAN")) {
            if (!SubdomainScanner.shouldStopScan.get()) {
                SubdomainScanner.shouldStopScan.set(true);
                ctx.writeAndFlush(Unpooled.copiedBuffer("🛑 Đã nhận yêu cầu dừng quét từ client.\n", StandardCharsets.UTF_8));
                System.out.println("🛑 Client yêu cầu dừng quét.");
            } else {
                ctx.writeAndFlush(Unpooled.copiedBuffer("⚠️ Yêu cầu dừng đã được gửi trước đó.\n", StandardCharsets.UTF_8));
            }
            return; // 🔴 BẮT BUỘC PHẢI CÓ RETURN ở đây để không xử lý phần JSON bên dưới
        }

        try {
            if (received.equalsIgnoreCase("GET_SERVER_PUBLIC_KEY")) {
                String base64Key = Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
                ctx.writeAndFlush(Unpooled.copiedBuffer("PUBLIC_KEY:" + base64Key + "\n", StandardCharsets.UTF_8));
                System.out.println("📤 Đã gửi public key cho client.");
                return;
            }

            Map<String, String> payload = mapper.readValue(received, new TypeReference<>() {});
            byte[] encAESKey = Base64.getDecoder().decode(payload.get("aesKey"));
            byte[] encAESIV = Base64.getDecoder().decode(payload.get("aesIV"));
            byte[] encPubKey = Base64.getDecoder().decode(payload.get("encryptedPubKey"));
            byte[] encMsg = Base64.getDecoder().decode(payload.get("encryptedMessage"));
            byte[] signature = Base64.getDecoder().decode(payload.get("signature"));

            // Giải mã AES
            byte[] aesKeyBytes = CryptoUtil.decryptRSA(encAESKey, serverPrivateKey);
            byte[] aesIVBytes = CryptoUtil.decryptRSA(encAESIV, serverPrivateKey);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Giải mã public key của client
            byte[] decryptedPubKey = CryptoUtil.decryptAES(encPubKey, aesKey, aesIVBytes);
            PublicKey clientPublicKey = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decryptedPubKey));
            String clientPublicKeyBase64 = Base64.getEncoder().encodeToString(decryptedPubKey);

            // Giải mã message
            byte[] decryptedMsg = CryptoUtil.decryptAES(encMsg, aesKey, aesIVBytes);
            String rawMessage = new String(decryptedMsg, StandardCharsets.UTF_8);
            System.out.println("📝 Message đã giải mã: " + rawMessage);

            // Xác thực chữ ký
            boolean verified = CryptoUtil.verifySHA256WithRSA(rawMessage.getBytes(), signature, clientPublicKey);
            if (!verified) {
                System.out.println("❌ Chữ ký không hợp lệ!");
                ctx.writeAndFlush(Unpooled.copiedBuffer("VERIFICATION_FAILED", StandardCharsets.UTF_8));
                return;
            }

            String[] parts = rawMessage.split("\\|\\|");
            if (parts.length != 3) {
                ctx.writeAndFlush(Unpooled.copiedBuffer("INVALID_MESSAGE_FORMAT", StandardCharsets.UTF_8));
                return;
            }

            String username = parts[0].trim();
            String domain = parts[1].trim();
            String wordlist = parts[2].trim();

            // Đăng ký/kiểm tra user
            boolean userValid = Database.registerUserKey(username, clientPublicKeyBase64);
            if (!userValid) {
                System.out.println("🚫 Public key không trùng khớp với user đã đăng ký: " + username);
                ctx.writeAndFlush(Unpooled.copiedBuffer("USER_KEY_MISMATCH", StandardCharsets.UTF_8));
                return;
            }

            // Ghi log
            Database.saveLog(
                username,
                clientPublicKeyBase64,
                Base64.getEncoder().encodeToString(aesKeyBytes),
                Base64.getEncoder().encodeToString(aesIVBytes),
                rawMessage
            );

            System.out.println("👤 Username : " + username);
            System.out.println("🌐 Đang scan subdomain...");
            System.out.println("→ Domain  : " + domain);
            System.out.println("→ Wordlist: " + wordlist);

            SubdomainScanner.scan(domain, wordlist, ctx);

        } catch (Exception e) {
            e.printStackTrace();
            ctx.writeAndFlush(Unpooled.copiedBuffer("VERIFICATION_FAILED", StandardCharsets.UTF_8));
        }
    }
}
