package com.secure.notes.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RequestValidationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 1. 從請求中獲取 'X-Valid-Request' 標頭
        String header = request.getHeader("X-Valid-Request");

        // 2. 檢查標頭是否存在或其值是否不為 "true"
        if (header == null || !header.equals("true")) {
            // 如果條件成立 (無效請求)，則回傳 400 Bad Request 錯誤
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid request");
            // 使用 return 關鍵字，中斷過濾器鏈的執行
            return;
        }

        // 3. 如果請求有效，則呼叫 filterChain.doFilter() 讓請求繼續
        filterChain.doFilter(request, response);

    }
}
