package com.mycompany.crypto;

import java.io.File;
import java.io.FileWriter;
import java.util.function.Consumer;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

public class NettyClientHandler extends SimpleChannelInboundHandler<String> {

    private final JTextArea outputArea;
    private final Consumer<String> callback;

    public NettyClientHandler(JTextArea outputArea, Consumer<String> callback) {
        this.outputArea = outputArea;
        this.callback = callback;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
        if (msg.startsWith("PUBLIC_KEY:")) {
            String base64Key = msg.replace("PUBLIC_KEY:", "").trim();

            File file = new File("received_server_public.pem");

            try (FileWriter fw = new FileWriter(file)) {
                fw.write("-----BEGIN PUBLIC KEY-----\n");
                fw.write(splitBase64Lines(base64Key));
                fw.write("-----END PUBLIC KEY-----\n");

                SwingUtilities.invokeLater(() ->
                    outputArea.append("📥 Đã nhận public key từ server và lưu tại: " + file.getAbsolutePath() + "\n")
                );

                if (callback != null) {
                    callback.accept("OK"); // thông báo về GUI
                }
            } catch (Exception e) {
                SwingUtilities.invokeLater(() ->
                    outputArea.append("❌ Không thể ghi public key: " + e.getMessage() + "\n")
                );
            } finally {
                ctx.close(); // đóng sau khi nhận key xong
            }
        } else {
            SwingUtilities.invokeLater(() ->
                outputArea.append("📨 Tin nhắn không hợp lệ từ server: " + msg + "\n")
            );
        }
    }

    private String splitBase64Lines(String base64) {
        StringBuilder sb = new StringBuilder();
        int len = base64.length();
        for (int i = 0; i < len; i += 64) {
            sb.append(base64, i, Math.min(len, i + 64)).append("\n");
        }
        return sb.toString();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        SwingUtilities.invokeLater(() ->
            outputArea.append("❌ Lỗi khi nhận public key: " + cause.getMessage() + "\n")
        );
        ctx.close();
    }
}
