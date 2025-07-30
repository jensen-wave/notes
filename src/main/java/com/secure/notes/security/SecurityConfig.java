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

import java.time.LocalDate;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Spring Security 的主要設定檔。
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
        // 設定 HTTP 請求的授權規則
        http.authorizeHttpRequests((requests) -> requests
                // 規則 1: 任何對 "/api/admin/**" 路徑的請求，使用者必須擁有 "ADMIN" 角色。
                // 注意：hasRole("ADMIN") 會自動尋找名為 "ROLE_ADMIN" 的權限，不需要手動加上 "ROLE_" 前綴。
                //.requestMatchers("/api/admin/**").hasRole("ADMIN")

                // 規則 2: 任何對 "/public/**" 路徑的請求，都允許存取 (permitAll)。
                // 這通常用於公開資源，如登入頁面、靜態檔案等，無需登入即可存取。
                //.requestMatchers("/public/**").permitAll()

                // 規則 3 (兜底規則): 除了上述規則之外的任何其他請求 (anyRequest)，都必須經過身份驗證 (authenticated)。
                .anyRequest().authenticated()
        );

        // 停用 CSRF (跨站請求偽造) 保護。
        // 對於無狀態的 RESTful API，通常會停用 CSRF，因為客戶端（如手機 App）不會像瀏覽器一樣自動發送 Cookie。
        http.csrf(AbstractHttpConfigurer::disable);

        // 啟用 HTTP Basic Authentication。
        // 這會彈出一個瀏覽器內建的簡單登入視窗，要求輸入使用者名稱和密碼。
        http.httpBasic(withDefaults());

        // 建構並返回 SecurityFilterChain 物件。
        return http.build();
    }

    /**
     * 定義一個 CommandLineRunner Bean，它會在 Spring Boot 應用程式啟動完成後自動執行。
     * 主要用途是在開發階段初始化資料庫，建立預設的角色和使用者帳號，方便測試。
     *
     * @param roleRepository Role 的資料存取庫。
     * @param userRepository User 的資料存取庫。
     * @return 一個 CommandLineRunner 實例。
     */
    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository,
                                      UserRepository userRepository,
                                      PasswordEncoder passwordEncoder) {
        return args -> {
            // 初始化 "USER" 角色：先嘗試尋找，如果不存在，則建立並儲存一個新的。
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));

            // 初始化 "ADMIN" 角色：同樣地，先尋找，若無則建立。
            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

            // 檢查名為 "user1" 的使用者是否存在，如果不存在，則建立一個普通使用者。
            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1", "user1@example.com", passwordEncoder().encode("password1"));
                // {noop} 表示密碼是純文字，未經加密。這只適用於開發和測試環境！
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
                User admin = new User("admin", "admin@example.com", passwordEncoder().encode("adminPass"));
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

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
