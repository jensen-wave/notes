package com.secure.notes.security.jwt;

import com.secure.notes.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 自訂的 JWT 身份驗證篩選器。
 * 這個篩選器會在每個請求進來時執行一次，負責攔截請求、驗證 JWT，
 * 並在驗證成功後設定 Spring Security 的安全上下文。
 */
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    // 自動注入 JWT 工具類，用於解析和驗證 Token。
    @Autowired
    private JwtUtils jwtUtils;

    // 自動注入使用者詳細資訊服務，用於根據使用者名稱從資料庫載入使用者資料。
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    // 用於記錄日誌的 Logger 實例。
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    /**
     * 篩選器的核心邏輯。
     * @param request  傳入的 HTTP 請求。
     * @param response 傳出的 HTTP 回應。
     * @param filterChain 篩選器鏈，用於將請求傳遞給下一個篩選器。
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());
        try {
            // 1. 從請求中解析出 JWT。
            String jwt = parseJwt(request);

            // 2. 檢查 JWT 是否存在且有效。
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                // 3. 如果 Token 有效，就從中解析出使用者名稱。
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                // 4. 根據使用者名稱，從資料庫載入使用者詳細資訊（包括權限）。
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // 5. 建立一個代表「已驗證成功」的 Authentication 物件。
                //    這個物件包含了使用者主體、憑證（此處為 null）和權限。
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null, // 因為是 Token 驗證，所以不需要密碼（憑證）。
                                userDetails.getAuthorities()); // 設定使用者的權限（角色）。
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                // 6. 將當前的請求詳細資訊（如 IP 位址）設定到 Authentication 物件中。
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 7. 【最關鍵的一步】更新 SecurityContextHolder，將 Authentication 物件設定進去。
                //    這個動作等同於告知 Spring Security：「這位使用者已經通過驗證了」。
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            // 如果在過程中發生任何錯誤，記錄日誌。
            logger.error("無法設定使用者身份驗證: {}", e);
        }

        // 8. 無論驗證成功與否，都必須呼叫 filterChain.doFilter 將請求傳遞下去。
        //    這樣才能讓請求繼續被後續的篩選器或控制器處理。
        filterChain.doFilter(request, response);
    }

    /**
     * 一個私有的輔助方法，用於從請求的 "Authorization" 標頭中提取 JWT。
     * @param request HTTP 請求。
     * @return 純粹的 JWT 字串，如果不存在則返回 null。
     */
    private String parseJwt(HttpServletRequest request) {
        // 呼叫 JwtUtils 中的方法來完成實際的提取邏輯。
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java: 提取到的 JWT: {}", jwt);
        return jwt;
    }
}