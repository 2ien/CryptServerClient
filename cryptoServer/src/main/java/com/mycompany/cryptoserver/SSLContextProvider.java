/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.cryptoserver;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

import java.io.InputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

public class SSLContextProvider {

    private static SslContext sslContext;

    public static SslContext getServerSslContext() throws Exception {
        if (sslContext == null) {
            // Đọc file từ resources/keys/
            InputStream certInput = SSLContextProvider.class.getClassLoader().getResourceAsStream("keys/server.crt");
            InputStream keyInput = SSLContextProvider.class.getClassLoader().getResourceAsStream("keys/server.key");

            if (certInput == null || keyInput == null) {
                throw new RuntimeException("Không tìm thấy server.crt hoặc server.key trong resources/keys/");
            }

            // Ghi ra file tạm (vì Netty yêu cầu File object)
            File certFile = File.createTempFile("cert", ".crt");
            File keyFile = File.createTempFile("key", ".key");

            Files.copy(certInput, certFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            Files.copy(keyInput, keyFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

            sslContext = SslContextBuilder
                    .forServer(certFile, keyFile)
                    .build();

            certFile.deleteOnExit();
            keyFile.deleteOnExit();
        }

        return sslContext;
    }
}


