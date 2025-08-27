package com.mycompany.cryptoserver;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;

public class ServerMain {

    public static void main(String[] args) {
        int port = 8080;
        SslContext sslContext;

        try {
            // Tạo SSL context từ chứng chỉ + private key
            sslContext = SSLContextProvider.getServerSslContext();
        } catch (Exception e) {
            System.err.println("❌ Lỗi khi khởi tạo SSLContext: " + e.getMessage());
            return;
        }

        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();

        try {
            ServerBootstrap b = new ServerBootstrap();
            b.group(bossGroup, workerGroup)
             .channel(NioServerSocketChannel.class)
             .childHandler(new ChannelInitializer<Channel>() {
                @Override
                protected void initChannel(Channel ch) {
                    ChannelPipeline pipeline = ch.pipeline();
                    pipeline.addLast(sslContext.newHandler(ch.alloc()));
                    try {
                        pipeline.addLast(new SecureServerHandler());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            });


            ChannelFuture f = b.bind(port).sync();
            System.out.println("✅ Server đang chạy tại port " + port);
            f.channel().closeFuture().sync();

        } catch (InterruptedException e) {
            System.err.println("❌ Lỗi trong quá trình chạy server: " + e.getMessage());
        } finally {
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
        }
    }
}
