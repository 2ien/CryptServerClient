package com.mycompany.cryptoserver;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;

public class SubdomainScanner {

    // ✅ Cho phép dừng từ bên ngoài (ví dụ Netty Handler)
    public static final AtomicBoolean shouldStopScan = new AtomicBoolean(false);

    public static void scan(String domain, String wordlistPath, ChannelHandlerContext ctx) throws IOException {
        shouldStopScan.set(false); // reset trước khi bắt đầu quét

        InputStream inputStream = SubdomainScanner.class.getClassLoader().getResourceAsStream(wordlistPath);
        if (inputStream == null) {
            throw new IOException("Không tìm thấy wordlist trong resources: " + wordlistPath);
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        List<String> found = new ArrayList<>();

        String line;
        int lineNumber = 1;

        while ((line = reader.readLine()) != null) {
            if (shouldStopScan.get()) {
                ctx.writeAndFlush(Unpooled.copiedBuffer("\n⏹️ Đã dừng quét theo yêu cầu người dùng.\n", StandardCharsets.UTF_8));
                
                // In các subdomain đã tìm thấy
                if (!found.isEmpty()) {
                    ctx.writeAndFlush(Unpooled.copiedBuffer("📋 Kết quả tạm thời trước khi dừng:\n", StandardCharsets.UTF_8));
                    for (String entry : found) {
                        ctx.writeAndFlush(Unpooled.copiedBuffer("- " + entry + "\n", StandardCharsets.UTF_8));
                    }
                } else {
                    ctx.writeAndFlush(Unpooled.copiedBuffer("⚠️ Không tìm thấy subdomain hợp lệ trước khi dừng.\n", StandardCharsets.UTF_8));
                }
                return; // dừng hẳn
            }

            String sub = line.trim();
            if (sub.isEmpty()) {
                lineNumber++;
                continue;
            }

            String fqdn = sub + "." + domain;
            String statusLine = String.format("[%06d] 🔎 Đang kiểm tra: %s\n", lineNumber, fqdn);
            ctx.writeAndFlush(Unpooled.copiedBuffer(statusLine, StandardCharsets.UTF_8));

            try {
                InetAddress address = InetAddress.getByName(fqdn);
                String resolved = fqdn + " -> " + address.getHostAddress();
                String resultLine = String.format("[%06d] ✅ Tìm thấy: %s\n", lineNumber, resolved);

                ctx.writeAndFlush(Unpooled.copiedBuffer(resultLine, StandardCharsets.UTF_8));
                found.add(String.format("[%06d] %s", lineNumber, resolved));
            } catch (UnknownHostException ignored) {
                // Không hiển thị nếu không resolve được
            }

            lineNumber++;
        }

        // ✅ Nếu chạy đến hết wordlist
        ctx.writeAndFlush(Unpooled.copiedBuffer("\n✅ Quét hoàn tất!\n", StandardCharsets.UTF_8));

        if (!found.isEmpty()) {
            ctx.writeAndFlush(Unpooled.copiedBuffer("📋 Tổng hợp subdomain hợp lệ:\n", StandardCharsets.UTF_8));
            for (String entry : found) {
                ctx.writeAndFlush(Unpooled.copiedBuffer("- " + entry + "\n", StandardCharsets.UTF_8));
            }
        } else {
            ctx.writeAndFlush(Unpooled.copiedBuffer("⚠️ Không tìm thấy subdomain hợp lệ.\n", StandardCharsets.UTF_8));
        }


    }
}
