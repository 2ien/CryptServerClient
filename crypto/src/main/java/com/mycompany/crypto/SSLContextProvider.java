/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.crypto;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

public class SSLContextProvider {

    private static SslContext sslContext;

    public static SslContext getClientSslContext() throws Exception {
        if (sslContext == null) {
            sslContext = SslContextBuilder.forClient()
                    .trustManager(InsecureTrustManagerFactory.INSTANCE) // Chấp nhận mọi chứng chỉ
                    .build();
        }
        return sslContext;
    }
}