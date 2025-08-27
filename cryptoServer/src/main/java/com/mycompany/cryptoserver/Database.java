package com.mycompany.cryptoserver;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class Database {

    private static final String DB_URL = "jdbc:sqlite:secure.db";

    // Tạo bảng nếu chưa có
    static {
        try {
            String schema = """
                CREATE TABLE IF NOT EXISTS secure_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    pubkey TEXT,
                    aes_key TEXT,
                    aes_iv TEXT,
                    message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """;

            String userSchema = """
                CREATE TABLE IF NOT EXISTS allowed_users (
                    username TEXT PRIMARY KEY,
                    public_key TEXT NOT NULL
                );
            """;

            try (Connection conn = DriverManager.getConnection(DB_URL);
                 Statement stmt = conn.createStatement()) {
                stmt.executeUpdate(schema);
                stmt.executeUpdate(userSchema);
                System.out.println("🗃️ SQLite: bảng secure_logs và allowed_users đã sẵn sàng.");
            }

        } catch (SQLException e) {
            System.err.println("❌ Lỗi tạo bảng SQLite:");
            e.printStackTrace();
        }
    }

    // Ghi log vào bảng
    public static void saveLog(String username, String pubkey, String aesKey, String aesIV, String message) {
        String sql = "INSERT INTO secure_logs(username, pubkey, aes_key, aes_iv, message) VALUES (?, ?, ?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            pstmt.setString(2, pubkey);
            pstmt.setString(3, aesKey);
            pstmt.setString(4, aesIV);
            pstmt.setString(5, message);
            pstmt.executeUpdate();

            System.out.println("✅ Đã lưu thông tin xác thực vào CSDL.");

        } catch (SQLException e) {
            System.err.println("❌ Lỗi lưu vào CSDL:");
            e.printStackTrace();
        }
    }

    // Đăng ký user nếu chưa có, kiểm tra khóa nếu đã có
    public static boolean registerUserKey(String username, String publicKeyBase64) {
        String checkSql = "SELECT public_key FROM allowed_users WHERE username = ?";
        String insertSql = "INSERT INTO allowed_users (username, public_key) VALUES (?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {

            checkStmt.setString(1, username);
            ResultSet rs = checkStmt.executeQuery();

            if (rs.next()) {
                String existingKey = rs.getString("public_key");
                return existingKey.equals(publicKeyBase64);  // ✅ Trùng thì cho phép, khác thì từ chối
            } else {
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
                    insertStmt.setString(1, username);
                    insertStmt.setString(2, publicKeyBase64);
                    insertStmt.executeUpdate();
                    System.out.println("📌 Đã đăng ký public key mới cho user: " + username);
                    return true;
                }
            }

        } catch (SQLException e) {
            System.err.println("❌ Lỗi khi đăng ký/check khóa public key:");
            e.printStackTrace();
            return false;
        }
    }

    // Kiểm tra user có tồn tại (ít dùng vì registerUserKey đã bao gồm check)
    public static boolean isUserAllowed(String username) {
        String sql = "SELECT 1 FROM allowed_users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            return rs.next();

        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // Quản trị viên cập nhật khóa mới cho user
    public static void allowUser(String username, String publicKeyBase64) {
        String sql = "INSERT OR REPLACE INTO allowed_users(username, public_key) VALUES (?, ?)";
        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            pstmt.setString(2, publicKeyBase64);
            pstmt.executeUpdate();
            System.out.println("✅ Đã cập nhật/cấp quyền cho user: " + username);

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
