/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.cryptoserver;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Base64;

public class CryptoUtil {

    // Ký SHA256withRSA
    public static byte[] signSHA256WithRSA(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    // Xác minh chữ ký
    public static boolean verifySHA256WithRSA(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(data);
        return verifier.verify(signature);
    }

    // Giải mã AES-CBC
    public static byte[] decryptAES(byte[] encrypted, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(encrypted);
    }

    // Mã hóa AES-CBC (nếu cần dùng thêm)
    public static byte[] encryptAES(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }

    // Giải mã RSA (AES key hoặc IV)
    public static byte[] decryptRSA(byte[] encrypted, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encrypted);
    }

    // Mã hóa RSA (nếu cần dùng thêm)
    public static byte[] encryptRSA(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    // Sinh AES key (nếu cần test thêm)
    public static SecretKey generateAESKey(int bitLength) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(bitLength);
        return keyGen.generateKey();
    }

    // Sinh IV ngẫu nhiên (nếu cần test thêm)
    public static byte[] generateIV(int length) {
        byte[] iv = new byte[length];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Base64 tiện dụng (nếu cần)
    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}