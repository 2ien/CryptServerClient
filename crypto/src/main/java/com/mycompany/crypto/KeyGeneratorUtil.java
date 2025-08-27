/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.crypto;
import java.io.FileWriter;
import java.io.Writer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyGeneratorUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void generateAndSaveKeyPair(String privatePath, String publicPath) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        try (Writer privWriter = new FileWriter(privatePath);
             JcaPEMWriter pemWriter = new JcaPEMWriter(privWriter)) {
            pemWriter.writeObject(keyPair.getPrivate());
        }

        try (Writer pubWriter = new FileWriter(publicPath);
             JcaPEMWriter pemWriter = new JcaPEMWriter(pubWriter)) {
            pemWriter.writeObject(keyPair.getPublic());
        }
    }
}
