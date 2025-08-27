package com.mycompany.crypto;

import java.awt.GridBagConstraints;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;

public class GUI extends javax.swing.JFrame {
    private File clientPublicKeyFile  = null;
    private File clientPrivateKeyFile = null;

    public GUI() {
        initComponents();
        jButtonSend.setEnabled(false);

        new Thread(() -> {
            try {
                NettyClient client = new NettyClient("localhost", 8080);
                client.start("GET_SERVER_PUBLIC_KEY", jTextArea1, (status) -> {
                    if ("OK".equals(status)) {
                        SwingUtilities.invokeLater(() -> {
                            jTextArea1.append("✔️ Đã nhận và lưu public key từ server.\n");
                            jButtonSend.setEnabled(true);
                        });
                    }
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    jTextArea1.append("❌ Không kết nối được server: " + e.getMessage() + "\n");
                });
            }
        }).start();
        setExtendedState(JFrame.MAXIMIZED_BOTH); // full screen
        setLocationRelativeTo(null); // căn giữa màn hình

    }   

    @SuppressWarnings("unchecked")
    private void initComponents() {
        jLabelText = new javax.swing.JLabel("Username:");
        jTextField = new javax.swing.JTextField(20);

        jTextArea1 = new javax.swing.JTextArea(25, 60);
        jTextArea1.setLineWrap(true);
        jTextArea1.setWrapStyleWord(true);
        jTextArea1.setEditable(false);
        jScrollPane1 = new javax.swing.JScrollPane(jTextArea1);

        jButtonPublicKey = new javax.swing.JButton("Public Key");
        jButtonPrivateKey = new javax.swing.JButton("Private Key");
        jButtonGenerateKey = new javax.swing.JButton("Tạo Khóa (PEM chuẩn)");
        jButtonSend = new javax.swing.JButton("Gửi");
        jButtonCancelScan = new javax.swing.JButton("🛑 Hủy quét");
        jButtonCancelScan.setEnabled(false); // mặc định ẩn
        jButtonCancelScan.addActionListener(evt -> jButtonCancelScanActionPerformed(evt));

        jButtonPublicKey.addActionListener(evt -> jButtonPublicClientKeyActionPerformed(evt));
        jButtonPrivateKey.addActionListener(evt -> jButtonPrivateClientKeyActionPerformed(evt));
        jButtonGenerateKey.addActionListener(evt -> jButtonGenerateKeyActionPerformed(evt));
        jButtonSend.addActionListener(evt -> jButtonSendActionPerformed(evt));

        // Bố cục tổng
        setLayout(new java.awt.BorderLayout());

        // ==== TOP: Nhập username ====
        JPanel topPanel = new JPanel();
        topPanel.add(jLabelText);
        topPanel.add(jTextField);
        add(topPanel, java.awt.BorderLayout.NORTH);

        // ==== CENTER: Khu vực log ====
        add(jScrollPane1, java.awt.BorderLayout.CENTER);

        // ==== RIGHT: Các nút chức năng ====
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new java.awt.GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new java.awt.Insets(10, 10, 10, 10);

        gbc.gridy = 0; rightPanel.add(jButtonPublicKey, gbc);
        gbc.gridy = 1; rightPanel.add(jButtonPrivateKey, gbc);
        gbc.gridy = 2; rightPanel.add(jButtonGenerateKey, gbc);
        gbc.gridy = 3; rightPanel.add(jButtonSend, gbc);
        gbc.gridy = 4; rightPanel.add(jButtonCancelScan, gbc);

        add(rightPanel, java.awt.BorderLayout.EAST);

        setTitle("Client Scanner");
        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setExtendedState(javax.swing.JFrame.MAXIMIZED_BOTH); // full screen
        setLocationRelativeTo(null); // căn giữa
        pack();
    }

    private void jButtonCancelScanActionPerformed(java.awt.event.ActionEvent evt) {
        new Thread(() -> {
            try {
                NettyClient client = new NettyClient("localhost", 8080);
                client.sendPlain("STOP_SCAN", jTextArea1);
                SwingUtilities.invokeLater(() -> {
                    jTextArea1.append("Đã gửi lệnh dừng quét đến server.\n");
                    jButtonCancelScan.setEnabled(false);
                });
            } catch (Exception ex) {
                ex.printStackTrace();
                SwingUtilities.invokeLater(() ->
                    jTextArea1.append("Gửi STOP_SCAN thất bại: " + ex.getMessage() + "\n")
                );
            }
        }).start();
    }

    private void jButtonGenerateKeyActionPerformed(java.awt.event.ActionEvent evt) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Chọn thư mục để lưu khóa");
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            int result = chooser.showSaveDialog(this);

            if (result == JFileChooser.APPROVE_OPTION) {
                File dir = chooser.getSelectedFile();

                // Tìm tên file không trùng
                File privateKeyFile, publicKeyFile;
                int index = 0;
                do {
                    String suffix = (index == 0) ? "" : String.valueOf(index);
                    privateKeyFile = new File(dir, "client" + suffix + ".key");
                    publicKeyFile  = new File(dir, "client" + suffix + ".pub");
                    index++;
                } while (privateKeyFile.exists() || publicKeyFile.exists());

                // Ghi file Private Key
                try (FileOutputStream fos = new FileOutputStream(privateKeyFile)) {
                    fos.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
                    fos.write(Base64.getMimeEncoder(64, "\n".getBytes()).encode(privateKey.getEncoded()));
                    fos.write("\n-----END PRIVATE KEY-----\n".getBytes());
                }

                // Ghi file Public Key
                try (FileOutputStream fos = new FileOutputStream(publicKeyFile)) {
                    fos.write("-----BEGIN PUBLIC KEY-----\n".getBytes());
                    fos.write(Base64.getMimeEncoder(64, "\n".getBytes()).encode(publicKey.getEncoded()));
                    fos.write("\n-----END PUBLIC KEY-----\n".getBytes());
                }

                clientPrivateKeyFile = privateKeyFile;
                clientPublicKeyFile = publicKeyFile;

                jButtonPrivateKey.setText(privateKeyFile.getName());
                jButtonPublicKey.setText(publicKeyFile.getName());

                jTextArea1.append("✅ Đã tạo cặp khóa thành công:\n");
                jTextArea1.append("🔐 Private: " + privateKeyFile.getAbsolutePath() + "\n");
                jTextArea1.append("🔓 Public : " + publicKeyFile.getAbsolutePath() + "\n");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this, "❌ Lỗi tạo khóa: " + ex.getMessage());
        }
    }


    private void jButtonPublicClientKeyActionPerformed(java.awt.event.ActionEvent evt) {
        JFileChooser filePublicKey = new JFileChooser();
        filePublicKey.setFileFilter(new FileNameExtensionFilter("Public Key Files", "pub", "pem", "crt", "cer"));
        int result = filePublicKey.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = filePublicKey.getSelectedFile();
            String fileName = selectedFile.getName().toLowerCase();
            if (!(fileName.endsWith(".pub") || fileName.endsWith(".pem") || fileName.endsWith(".crt") || fileName.endsWith(".cer"))) {
                JOptionPane.showMessageDialog(this, "File không đúng định dạng!", "Lỗi", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (isValidPublicKey(selectedFile)) {
                jButtonPublicKey.setText(selectedFile.getName());
                clientPublicKeyFile = selectedFile;
            } else {
                JOptionPane.showMessageDialog(this, "Nội dung không phải public key hợp lệ!", "Lỗi", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void jButtonPrivateClientKeyActionPerformed(java.awt.event.ActionEvent evt) {
        JFileChooser filePrivateKey = new JFileChooser();
        filePrivateKey.setFileFilter(new FileNameExtensionFilter("Private Key Files", "key", "pem", "pfx", "p12"));
        int result = filePrivateKey.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = filePrivateKey.getSelectedFile();
            String fileName = selectedFile.getName().toLowerCase();
            if (!(fileName.endsWith(".key") || fileName.endsWith(".pem") || fileName.endsWith(".pfx") || fileName.endsWith(".p12"))) {
                JOptionPane.showMessageDialog(this, "File không đúng định dạng private key!", "Lỗi", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (isValidPrivateKey(selectedFile)) {
                jButtonPrivateKey.setText(selectedFile.getName());
                clientPrivateKeyFile = selectedFile;
            } else {
                JOptionPane.showMessageDialog(this, "Nội dung không phải private key hợp lệ!", "Lỗi", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void jButtonSendActionPerformed(java.awt.event.ActionEvent evt) {
        String username = jTextField.getText().trim(); // Lấy username từ ô nhập
        if (username.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Vui lòng nhập Username");
            return;
        }

        String domain = "huflit.edu.vn";
        String wordlist = "scan/subdomains-top1million-110000.txt";
        String msg = username + "||" + domain + "||" + wordlist;

        if (clientPrivateKeyFile == null) {
            JOptionPane.showMessageDialog(this, "Vui lòng chọn Private Key của bạn");
            return;
        }

        File serverPublicKeyFile = new File("received_server_public.pem");
        if (!serverPublicKeyFile.exists()) {
            JOptionPane.showMessageDialog(this, "Chưa nhận được Public Key từ Server!", "Lỗi", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            SecureMessageBuilder builder = new SecureMessageBuilder();
            String jsonPayload = builder.buildSecurePayload(
                msg,
                clientPrivateKeyFile,
                serverPublicKeyFile,
                clientPublicKeyFile
            );

            jTextArea1.append("✔ Payload đã được ký và mã hóa.\n");
            jButtonCancelScan.setEnabled(true); // cho phép bấm "Hủy"

            // Gửi qua luồng riêng
            new Thread(() -> {
                try {
                    NettyClient client = new NettyClient("localhost", 8080);
                    client.start(jsonPayload, jTextArea1);
                    SwingUtilities.invokeLater(() ->
                        jTextArea1.append("📤 Đã gửi JSON đến server.\n")
                    );
                } catch (Exception ex) {
                    ex.printStackTrace();
                    SwingUtilities.invokeLater(() ->
                        jTextArea1.append("❌ Lỗi khi gửi JSON: " + ex.getMessage() + "\n")
                    );
                }
            }).start();

        } catch (Exception ex) {
            ex.printStackTrace();
            jTextArea1.append("❌ Lỗi gửi payload: " + ex.getMessage() + "\n");
        }
    }




    private Boolean isValidPublicKey(File file) {
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.contains("BEGIN PUBLIC KEY") ||
                    line.contains("BEGIN RSA PUBLIC KEY") ||
                    line.contains("BEGIN CERTIFICATE")) {
                    return true;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private Boolean isValidPrivateKey(File file) {
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.contains("BEGIN PRIVATE KEY") ||
                    line.contains("BEGIN RSA PRIVATE KEY") ||
                    line.contains("BEGIN CERTIFICATE")) {
                    return true;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    // Swing component declarations
    private javax.swing.JButton jButtonPrivateKey;
    private javax.swing.JButton jButtonPublicKey;
    private javax.swing.JButton jButtonSend;
    private javax.swing.JButton jButtonGenerateKey;
    private javax.swing.JLabel jLabelText;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JTextField jTextField;
    private javax.swing.JButton jButtonCancelScan;
}