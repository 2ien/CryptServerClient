package com.mycompany.crypto;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.DelimiterBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;

import javax.swing.*;
import java.util.function.Consumer;

public class NettyClient {

    private final String host;
    private final int port;

    public NettyClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    // Gửi payload JSON qua ClientHandler
    public void start(String jsonPayload, JTextArea outputArea) {
        EventLoopGroup group = new NioEventLoopGroup();

        try {
            SslContext sslCtx = SSLContextProvider.getClientSslContext();

            Bootstrap b = new Bootstrap();
            b.group(group)
             .channel(NioSocketChannel.class)
             .handler(new ChannelInitializer<Channel>() {
                 @Override
                 protected void initChannel(Channel ch) {
                     ChannelPipeline pipeline = ch.pipeline();
                     pipeline.addLast(sslCtx.newHandler(ch.alloc(), host, port));
                     pipeline.addLast(new ClientHandler(jsonPayload, outputArea));
                 }
             });

            ChannelFuture f = b.connect(host, port).sync();
            f.channel().closeFuture().sync();

        } catch (Exception e) {
            SwingUtilities.invokeLater(() ->
                    outputArea.append("❌ Lỗi: " + e.getMessage() + "\n"));
        } finally {
            group.shutdownGracefully();
        }
    }
    public void sendPlain(String message, JTextArea outputArea) {
        EventLoopGroup group = new NioEventLoopGroup();

        try {
            SslContext sslCtx = SSLContextProvider.getClientSslContext();

            Bootstrap b = new Bootstrap();
            b.group(group)
            .channel(NioSocketChannel.class)
            .handler(new ChannelInitializer<Channel>() {
                @Override
                protected void initChannel(Channel ch) {
                    ChannelPipeline pipeline = ch.pipeline();
                    pipeline.addLast(sslCtx.newHandler(ch.alloc(), host, port));
                    pipeline.addLast(new DelimiterBasedFrameDecoder(8192, Unpooled.wrappedBuffer("\n".getBytes())));
                    pipeline.addLast(new StringDecoder());
                    pipeline.addLast(new StringEncoder()); 
                    pipeline.addLast(new SimpleChannelInboundHandler<String>() {
                        @Override
                        protected void channelRead0(ChannelHandlerContext ctx, String msg) {
                            SwingUtilities.invokeLater(() -> {
                                outputArea.append("Phản hồi từ server: " + msg + "\n");
                            });
                            ctx.close();
                        }
                        @Override
                        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                            SwingUtilities.invokeLater(() ->
                                outputArea.append("Lỗi khi gửi STOP_SCAN: " + cause.getMessage() + "\n"));
                            ctx.close();
                        }
                    });
                }
            });

            ChannelFuture f = b.connect(host, port).sync();
            f.channel().writeAndFlush(message + "\n");

            // Đợi đến khi server phản hồi xong -> đóng kênh
            f.channel().closeFuture().sync();

        } catch (Exception e) {
            SwingUtilities.invokeLater(() -> {
                outputArea.append("❌ Lỗi khi gửi lệnh STOP_SCAN: " + e.getMessage() + "\n");
            });
        } finally {
            group.shutdownGracefully();
        }
    }


    // ✅ Dùng để kết nối lấy PUBLIC_KEY, dùng NettyClientHandler
    public void start(String message, JTextArea outputArea, Consumer<String> callback) {
        EventLoopGroup group = new NioEventLoopGroup();

        try {
            SslContext sslCtx = SSLContextProvider.getClientSslContext();

            Bootstrap b = new Bootstrap();
            b.group(group)
             .channel(NioSocketChannel.class)
             .handler(new ChannelInitializer<Channel>() {
                 @Override
                 protected void initChannel(Channel ch) {
                     ChannelPipeline pipeline = ch.pipeline();
                     pipeline.addLast(sslCtx.newHandler(ch.alloc(), host, port));
                     pipeline.addLast(new DelimiterBasedFrameDecoder(8192, Unpooled.wrappedBuffer("\n".getBytes())));
                     pipeline.addLast(new StringDecoder());
                     pipeline.addLast(new StringEncoder());
                     pipeline.addLast(new NettyClientHandler(outputArea, callback)); // 👈 handler nhận PUBLIC_KEY
                 }
             });

            ChannelFuture f = b.connect(host, port).sync();
            f.channel().writeAndFlush(message + "\n");
            f.channel().closeFuture().sync();

        } catch (Exception e) {
            SwingUtilities.invokeLater(() ->
                    outputArea.append("❌ Lỗi khi nhận public key: " + e.getMessage() + "\n"));
        } finally {
            group.shutdownGracefully();
        }
    }
}
