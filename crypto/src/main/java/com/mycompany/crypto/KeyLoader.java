/*
    * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
    * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
    */
package com.mycompany.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 *
 * @author 2ien
 */
public class KeyLoader {
    public static PrivateKey loadPrivateKey(File file) throws Exception{
        String pem = readPEM(file,"PRIVATE KEY");
        byte[] keyBytes = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
    public static PublicKey loadPublicKey(File file) throws Exception{
        String pem = readPEM(file,"PUBLIC KEY");
        byte[] keyBytes = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static String readPEM(File file, String type) throws Exception {
        StringBuilder sb = new StringBuilder();
        boolean inKey = false;

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("-----BEGIN " + type)) {
                    inKey = true;
                } else if (line.startsWith("-----END " + type)) {
                    break;
                } else if (inKey) {
                    sb.append(line);
                }
            }
        }
        return sb.toString();
    }

}
