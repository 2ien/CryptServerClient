package com.mycompany.crypto;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.CharsetUtil;

public class ClientHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private final String jsonPayload;
    private final JTextArea outputArea;

    public ClientHandler(String jsonPayload, JTextArea outputArea) {
        this.jsonPayload = jsonPayload;
        this.outputArea = outputArea;
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        // Gửi JSON khi kết nối được thiết lập
        ctx.writeAndFlush(ctx.alloc().buffer().writeBytes((jsonPayload + "\n").getBytes(CharsetUtil.UTF_8)));
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
        String response = msg.toString(CharsetUtil.UTF_8);

        SwingUtilities.invokeLater(() -> {
            outputArea.append("📨 Phản hồi từ server: " + response + "\n");
        });
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append("❌ Kết nối lỗi: " + cause.getMessage() + "\n");
        });
        ctx.close();
    }
}
