package com.secure.notes.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class CustomLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 在請求傳遞到下一個過濾器之前，印出請求的 URI
        System.out.println("CustomLoggingFilter - Request URI: " + request.getRequestURI());

        // 將請求傳遞給過濾鏈中的下一個過濾器
        filterChain.doFilter(request, response);

        // 在請求處理完畢後，印出回應的狀態碼
        System.out.println("CustomLoggingFilter - Response Status: " + response.getStatus());
    }
}
