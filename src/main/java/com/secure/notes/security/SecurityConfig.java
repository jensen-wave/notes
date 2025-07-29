package com.secure.notes.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource; // 要用 JDBC 驗證，需注入資料來源

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

    // 建立 JDBC-based UserDetailsService，從資料庫取得帳號資料
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        // 使用 JDBC 的方式從資料庫存取使用者資訊
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);

        // 檢查是否已存在使用者 "user1"，若無則建立 USER 角色帳號
        if (!manager.userExists("user1")) {
            manager.createUser(
                    User.withUsername("user1")
                            .password("{noop}password1") // {noop} 代表密碼未加密（僅限開發測試）
                            .roles("USER") // 賦予 USER 角色
                            .build()
            );
        }

        // 檢查是否已存在使用者 "admin"，若無則建立 ADMIN 角色帳號
        if (!manager.userExists("admin")) {
            manager.createUser(
                    User.withUsername("admin")
                            .password("{noop}adminPass") // 密碼未加密
                            .roles("ADMIN") // 賦予 ADMIN 角色
                            .build()
            );
        }

        // 返回 UserDetailsService 實例
        return manager;
    }
}
