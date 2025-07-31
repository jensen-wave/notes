package com.secure.notes.security;

import com.secure.notes.models.AppRole;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.time.LocalDate;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Spring Security 的主要設定檔。
 *
 * @Configuration 標示這是一個 Spring 的設定類別，Spring 容器會掃描並處理其中的 Bean。
 */
@Configuration
/**
 * @EnableMethodSecurity 啟用方法層級的安全性控制。
 * 這允許我們在個別的 Controller 方法上使用 @PreAuthorize, @PostAuthorize, @Secured 等註解來進行更細粒度的權限控制。
 * - prePostEnabled = true: 啟用 @PreAuthorize 和 @PostAuthorize 註解。
 * - securedEnabled = true: 啟用 @Secured 註解。
 * - jsr250Enabled = true: 啟用 JSR-250 標準的 @RolesAllowed 註解。
 */
@EnableMethodSecurity(
        prePostEnabled = true,
        securedEnabled = true,
        jsr250Enabled = true)
public class SecurityConfig {

    /**
     * 定義一個 SecurityFilterChain Bean，這是 Spring Security 6.x 之後的核心設定方式。
     * 它定義了 HTTP 請求的安全處理規則鏈。
     *
     * @param http HttpSecurity 物件，用來建構安全規則。
     * @return 一個建構好的 SecurityFilterChain 實例。
     * @throws Exception 可能拋出的例外。
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // --- 1. 設定 CSRF (跨站請求偽造) 保護 ---
        http.csrf(csrf ->
                csrf
                        // 規則 1.1: 忽略特定路徑的 CSRF 保護。
                        // 所有符合 "/api/auth/public/**" 模式的請求將不會進行 CSRF Token 驗證。
                        // 這適用於不需要保護的公開 API。
                        .ignoringRequestMatchers("/api/auth/public/**")
                        // 規則 1.2: 設定 CSRF Token 的儲存庫。
                        // CookieCsrfTokenRepository 會將 Token 存放在 Cookie 中。
                        // withHttpOnlyFalse() 允許客戶端的 JavaScript 讀取這個 Cookie，這對於 SPA (單頁應用) 前端至關重要。
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));

        // --- 2. 設定 HTTP 請求的授權規則 ---
        http.authorizeHttpRequests((requests) -> requests
                // 規則 2.1: 任何對 "/api/csrf-token" 路徑的請求，都允許存取 (permitAll)。
                // 這讓未登入的使用者也能獲取 CSRF Token。
                .requestMatchers("/api/csrf-token").permitAll()
                // 規則 2.2 (兜底規則): 除了上述規則之外的任何其他請求 (anyRequest)，都必須經過身份驗證 (authenticated)。
                .anyRequest().authenticated()
        );

        // --- 3. 設定認證方式 ---
        // 啟用 HTTP Basic Authentication。
        // 這會彈出一個瀏覽器內建的簡單登入視窗，要求輸入使用者名稱和密碼。
        http.httpBasic(withDefaults());
        // 啟用表單登入 (Form Login)。
        // 這會提供一個預設的登入頁面。
        http.formLogin(withDefaults());

        // --- 4. 建構並返回 SecurityFilterChain 物件 ---
        return http.build();
    }

    /**
     * 定義一個密碼編碼器 Bean。
     * 使用 BCrypt 演算法來安全地雜湊和驗證密碼。
     *
     * @return 一個 BCryptPasswordEncoder 實例。
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 定義一個 CommandLineRunner Bean，它會在 Spring Boot 應用程式啟動完成後自動執行。
     * 主要用途是在開發階段初始化資料庫，建立預設的角色和使用者帳號，方便測試。
     *
     * @param roleRepository Role 的資料存取庫。
     * @param userRepository User 的資料存取庫。
     * @param passwordEncoder 密碼編碼器，用於加密預設密碼。
     * @return 一個 CommandLineRunner 實例。
     */
    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository,
                                      UserRepository userRepository,
                                      PasswordEncoder passwordEncoder) {
        return args -> {
            // --- 初始化角色 ---
            // 初始化 "USER" 角色：先嘗試尋找，如果不存在，則建立並儲存一個新的。
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));

            // 初始化 "ADMIN" 角色：同樣地，先尋找，若無則建立。
            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

            // --- 初始化使用者 ---
            // 檢查名為 "user1" 的使用者是否存在，如果不存在，則建立一個普通使用者。
            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1", "user1@example.com",
                        passwordEncoder.encode("password1")); // 使用 passwordEncoder 加密密碼
                user1.setAccountNonLocked(true); // 帳號未鎖定
                user1.setAccountNonExpired(true); // 帳號未過期
                user1.setCredentialsNonExpired(true); // 憑證未過期
                user1.setEnabled(true); // 帳號已啟用
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1)); // 憑證一年後過期
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1)); // 帳號一年後過期
                user1.setTwoFactorEnabled(false); // 禁用兩步驟驗證
                user1.setSignUpMethod("email"); // 註冊方式
                user1.setRole(userRole); // 設定角色為 "USER"
                userRepository.save(user1); // 儲存到資料庫
            }

            // 檢查名為 "admin" 的使用者是否存在，如果不存在，則建立一個管理員。
            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin", "admin@example.com",
                        passwordEncoder.encode("adminPass")); // 使用 passwordEncoder 加密密碼
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole); // 設定角色為 "ADMIN"
                userRepository.save(admin); // 儲存到資料庫
            }
        };
    }
}
