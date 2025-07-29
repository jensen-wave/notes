package com.secure.notes.security;

import com.secure.notes.models.AppRole;
import com.secure.notes.models.Role;
import com.secure.notes.models.User;
import com.secure.notes.repositories.RoleRepository;
import com.secure.notes.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource; // 要用 JDBC 驗證，需注入資料來源

import java.time.LocalDate;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration // 告訴 Spring 這是一個組態類別，會自動建立 Spring Bean
public class SecurityConfig {

    // 建立 SecurityFilterChain Bean，配置安全策略
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // 1. 所有請求都要通過身份驗證
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());

        // 2. 關閉 CSRF 保護（適用於 REST API 或非瀏覽器環境）
        http.csrf(csrf -> csrf.disable());

        // 3. 啟用 HTTP Basic 認證方式（簡單帳密視窗）
        http.httpBasic(withDefaults());

        // 4. 返回建構好的 SecurityFilterChain 物件
        return http.build();
    }

//    // 建立 JDBC-based UserDetailsService，從資料庫取得帳號資料
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        // 使用 JDBC 的方式從資料庫存取使用者資訊
//        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
//
//        // 檢查是否已存在使用者 "user1"，若無則建立 USER 角色帳號
//        if (!manager.userExists("user1")) {
//            manager.createUser(
//                    User.withUsername("user1")
//                            .password("{noop}password1") // {noop} 代表密碼未加密（僅限開發測試）
//                            .roles("USER") // 賦予 USER 角色
//                            .build()
//            );
//        }
//
//        // 檢查是否已存在使用者 "admin"，若無則建立 ADMIN 角色帳號
//        if (!manager.userExists("admin")) {
//            manager.createUser(
//                    User.withUsername("admin")
//                            .password("{noop}adminPass") // 密碼未加密
//                            .roles("ADMIN") // 賦予 ADMIN 角色
//                            .build()
//            );
//        }
//
//        // 返回 UserDetailsService 實例
//        return manager;
//    }

    @Bean
    public CommandLineRunner initData(RoleRepository roleRepository, UserRepository userRepository) {
        return args -> {
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));

            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

            if (!userRepository.existsByUserName("user1")) {
                User user1 = new User("user1", "user1@example.com", "{noop}password1");
                user1.setAccountNonLocked(false);
                user1.setAccountNonExpired(true);
                user1.setCredentialsNonExpired(true);
                user1.setEnabled(true);
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user1.setTwoFactorEnabled(false);
                user1.setSignUpMethod("email");
                user1.setRole(userRole);
                userRepository.save(user1);
            }

            if (!userRepository.existsByUserName("admin")) {
                User admin = new User("admin", "admin@example.com", "{noop}adminPass");
                admin.setAccountNonLocked(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setEnabled(true);
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
    }
}
