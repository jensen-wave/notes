package com.secure.notes.controllers;

// 導入相關類別和套件
import com.secure.notes.security.jwt.JwtUtils;           // 自定義 JWT 工具類
import com.secure.notes.security.request.LoginRequest;   // 登入請求資料傳輸物件
import com.secure.notes.security.response.LoginResponse; // 登入回應資料傳輸物件
import org.springframework.beans.factory.annotation.Autowired;       // Spring 依賴注入註解
import org.springframework.http.HttpStatus;                         // HTTP 狀態碼列舉
import org.springframework.http.ResponseEntity;                     // Spring HTTP 回應封裝類
import org.springframework.security.authentication.AuthenticationManager;           // Spring Security 認證管理器介面
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; // 用戶名密碼認證 Token 類
import org.springframework.security.core.Authentication;            // Spring Security 認證結果介面
import org.springframework.security.core.AuthenticationException;   // Spring Security 認證失敗異常基類
import org.springframework.security.core.context.SecurityContextHolder; // Security 上下文持有者，管理當前線程的安全資訊
import org.springframework.security.core.userdetails.UserDetails;   // Spring Security 用戶詳細資訊介面
import org.springframework.web.bind.annotation.PostMapping;         // Spring Web POST 請求映射註解
import org.springframework.web.bind.annotation.RequestBody;         // 請求體參數註解
import org.springframework.web.bind.annotation.RequestMapping;      // 請求路徑映射註解
import org.springframework.web.bind.annotation.RestController;      // REST 控制器註解

import java.util.HashMap;      // Java HashMap 實現類
import java.util.List;         // Java List 介面
import java.util.Map;          // Java Map 介面
import java.util.stream.Collectors; // Java Stream API 收集器工具

/**
 * 認證控制器類別
 * 負責處理用戶登入認證相關的 HTTP 請求
 * 實現 JWT 基於 Token 的認證機制
 */
@RestController                 // 標記為 REST 控制器，自動將方法回傳值序列化為 JSON
@RequestMapping("/api/auth")    // 定義控制器的基礎路徑，所有端點都會以 /api/auth 開頭
public class AuthController {

    /**
     * JWT 工具類別依賴注入
     *
     * 背後邏輯：
     * - Spring 容器會自動查找 JwtUtils 類型的 Bean
     * - 通常在配置類中使用 @Component 或 @Service 註解定義
     * - 用於生成、解析和驗證 JWT Token
     */
    @Autowired
    JwtUtils jwtUtils;

    /**
     * Spring Security 認證管理器依賴注入
     *
     * 背後邏輯：
     * - 實際實現通常是 ProviderManager
     * - 內部包含多個 AuthenticationProvider（如 DaoAuthenticationProvider）
     * - 每個 Provider 負責處理特定類型的認證（如用戶名密碼認證）
     * - 在 SecurityConfig 配置類中定義和配置
     */
    @Autowired
    AuthenticationManager authenticationManager;

    /**
     * 用戶登入認證端點
     * 處理用戶登入請求，驗證身份並回傳 JWT Token
     *
     * @param loginRequest 包含用戶名和密碼的登入請求物件
     * @return ResponseEntity<?> 認證結果回應，成功時包含 JWT Token 和用戶資訊
     */
    @PostMapping("/public/signin") // 映射到 POST /api/auth/public/signin
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        // 宣告認證結果變數，稍後存儲認證成功的 Authentication 物件
        Authentication authentication;

        try {
            /**
             * 關鍵認證步驟：執行用戶身份驗證
             *
             * 步驟分解：
             * 1. 創建未認證的 UsernamePasswordAuthenticationToken
             *    - 包含用戶輸入的用戶名和明文密碼
             *    - 此時 isAuthenticated() 返回 false
             *
             * 2. authenticationManager.authenticate() 背後的完整流程：
             *    a) ProviderManager 遍歷所有 AuthenticationProvider
             *    b) 找到支援 UsernamePasswordAuthenticationToken 的 Provider（通常是 DaoAuthenticationProvider）
             *    c) DaoAuthenticationProvider 執行以下步驟：
             *       - 調用 UserDetailsService.loadUserByUsername() 從資料庫查詢用戶
             *       - 檢查用戶帳戶狀態（是否啟用、未過期、未鎖定等）
             *       - 使用 PasswordEncoder 比對輸入密碼與資料庫中的加密密碼
             *       - 如果驗證成功，創建已認證的 Authentication 物件
             *
             * 3. 回傳已認證的 Authentication 物件：
             *    - principal: UserDetails 物件（包含用戶詳細資訊）
             *    - credentials: null（密碼已清空，基於安全考量）
             *    - authorities: 用戶的權限列表
             *    - isAuthenticated(): true
             */
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),  // 用戶輸入的用戶名
                            loginRequest.getPassword()   // 用戶輸入的明文密碼
                    ));

        } catch (AuthenticationException exception) {
            /**
             * 認證失敗處理
             *
             * AuthenticationException 的可能子類型：
             * - BadCredentialsException: 用戶名或密碼錯誤
             * - UsernameNotFoundException: 用戶不存在
             * - AccountExpiredException: 帳戶已過期
             * - DisabledException: 帳戶已停用
             * - LockedException: 帳戶已鎖定
             */

            // 構建錯誤回應的資料結構
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");  // 錯誤訊息（出於安全考量，不透露具體失敗原因）
            map.put("status", false);               // 認證狀態：失敗

            // 回傳 HTTP 404 Not Found 和錯誤資訊
            // 注意：使用 404 而非 401 可能是為了隱藏 API 端點的存在
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        /**
         * 認證成功後的處理流程
         *
         * 設定安全上下文：
         * - SecurityContextHolder 是 ThreadLocal 基礎的容器
         * - 儲存當前線程（請求）的安全資訊
         * - 後續的安全檢查和授權決策會使用這個上下文
         * - 在請求結束時，Spring Security 會自動清理這個上下文
         */
        SecurityContextHolder.getContext().setAuthentication(authentication);

        /**
         * 提取認證主體（用戶詳細資訊）
         *
         * 背後邏輯：
         * - getPrincipal() 回傳認證的主體物件
         * - 在成功的用戶名密碼認證中，這通常是 UserDetails 實現
         * - UserDetails 包含：用戶名、加密密碼、帳戶狀態、權限列表等
         * - 這個物件是在 UserDetailsService.loadUserByUsername() 中創建的
         */
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        /**
         * 生成 JWT Token
         *
         * 背後邏輯（JwtUtils.generateTokenFromUsername 可能的實現）：
         * 1. 從 UserDetails 提取用戶名和權限資訊
         * 2. 創建 JWT Claims（聲明），包含：
         *    - sub（subject）: 用戶名
         *    - iat（issued at）: 發行時間
         *    - exp（expiration）: 過期時間
         *    - 自定義 claims: 如角色列表
         * 3. 使用密鑰和指定演算法（如 HS256）對 Token 進行簽名
         * 4. 回傳完整的 JWT Token 字串
         */
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        /**
         * 提取用戶角色權限列表
         *
         * 流程說明：
         * 1. getAuthorities() 回傳 Collection<? extends GrantedAuthority>
         * 2. 每個 GrantedAuthority 代表用戶的一個權限或角色
         * 3. getAuthority() 回傳權限的字串表示（如 "ROLE_USER", "ROLE_ADMIN"）
         * 4. 使用 Stream API 將權限物件轉換為字串列表
         * 5. 這個列表將包含在回應中，供前端進行權限控制
         */
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())           // 將 GrantedAuthority 轉換為字串
                .collect(Collectors.toList());              // 收集為 List<String>

        /**
         * 構建登入成功回應物件
         *
         * LoginResponse 通常包含：
         * - username: 用戶名（用於前端顯示）
         * - roles: 角色列表（用於前端權限控制）
         * - jwtToken: JWT Token（用於後續 API 請求認證）
         */
        LoginResponse response = new LoginResponse(
                userDetails.getUsername(),  // 已認證用戶的用戶名
                roles,                      // 用戶角色權限列表
                jwtToken                    // 生成的 JWT Token
        );

        /**
         * 回傳成功回應
         *
         * ResponseEntity.ok() 相當於：
         * - HTTP 狀態碼：200 OK
         * - 回應體：LoginResponse 物件（會被自動序列化為 JSON）
         * - Content-Type: application/json（由 @RestController 自動設定）
         *
         * 前端收到回應後通常會：
         * 1. 儲存 JWT Token（localStorage 或 cookie）
         * 2. 在後續 API 請求的 Authorization header 中攜帶 Token
         * 3. 根據 roles 列表控制 UI 元素的顯示和功能權限
         */
        return ResponseEntity.ok(response);
    }
}