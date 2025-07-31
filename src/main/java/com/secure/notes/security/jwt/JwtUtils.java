package com.secure.notes.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

/**
 * 用於處理 JSON Web Token (JWT) 的工具類。
 * 這個類別提供了生成、解析和驗證 JWT 的方法。
 * 它被標記為 Spring 的 @Component，以便由 IoC 容器管理。
 */
@Component
public class JwtUtils {
    // 用於記錄事件和錯誤的 Logger 實例。
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    // 從 application.properties 檔案中注入 JWT 密鑰。
    // 這個密鑰用於簽署和驗證 Token。
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    // 從 application.properties 檔案中注入 JWT 的過期時間（以毫秒為單位）。
    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    /**
     * 從 HTTP 請求的 "Authorization" 標頭中提取 JWT。
     * 預期的格式是 "Bearer <token>"。
     *
     * @param request 傳入的 HttpServletRequest。
     * @return 如果找到且格式正確，則返回 JWT 字串；否則返回 null。
     */
    public String getJwtFromHeader(HttpServletRequest request) {
        // 獲取 "Authorization" 標頭的值。
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);

        // 檢查標頭是否不為 null 且以 "Bearer " 開頭。
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            // 透過移除 "Bearer " 前綴（7個字元）來提取 Token。
            return bearerToken.substring(7);
        }
        // 如果標頭缺失或格式不正確，則返回 null。
        return null;
    }

    /**
     * 為指定的使用者生成一個 JWT。
     *
     * @param userDetails 包含使用者資訊的 UserDetails 物件。
     * @return 一個緊湊且 URL 安全的 JWT 字串。
     */
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();

        // 使用 Jwts builder 來建構 Token。
        return Jwts.builder()
                // 設定 Token 的 'subject'（主題），通常是使用者名稱。
                .subject(username)
                // 設定 'issued at'（簽發時間）為當前時間。
                .issuedAt(new Date())
                // 設定 'expiration'（過期時間）。
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                // 使用指定的演算法和密鑰對 Token 進行簽名。
                .signWith(key())
                // 建構 Token 並將其序列化為一個緊湊、URL 安全的字串。
                .compact();
    }

    /**
     * 解析一個 JWT 並從其 payload（負載）中提取使用者名稱（subject）。
     *
     * @param token 要解析的 JWT 字串。
     * @return Token 中包含的使用者名稱。
     */
    public String getUserNameFromJwtToken(String token) {
        // 使用 Jwts parser 來驗證和解析 Token。
        return Jwts.parser()
                // 提供密鑰以驗證 Token 的簽名。
                .verifyWith((SecretKey) key())
                // 建構解析器。
                .build()
                // 從已簽名的 Token 中解析 claims。如果簽名無效，此處會拋出異常。
                .parseSignedClaims(token)
                // 獲取 Token 的 payload（負載/主體）。
                .getPayload()
                // 從 payload 中獲取 'subject' claim。
                .getSubject();
    }

    /**
     * 一個私有的輔助方法，用於從 Base64 編碼的密鑰生成簽名用的 Key 物件。
     *
     * @return 用於簽名和驗證的 Key 物件。
     */
    private Key key() {
        // 將 application.properties 中的 Base64 編碼密鑰字串解碼。
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        // 從解碼後的位元組陣列創建一個 HMAC-SHA 密鑰。
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * 驗證給定的 JWT。它會檢查簽名是否有效以及 Token 是否過期。
     *
     * @param authToken 要驗證的 JWT 字串。
     * @return 如果 Token 有效則返回 true，否則返回 false。
     */
    public boolean validateJwtToken(String authToken) {
        try {
            // 嘗試解析 Token。如果此操作成功且未拋出異常，
            // 表示 Token 的簽名有效且尚未過期。
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("無效的 JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token 已過期: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("不支援的 JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims 字串為空: {}", e.getMessage());
        }

        // 如果捕獲到任何異常，表示 Token 無效。
        return false;
    }
}
