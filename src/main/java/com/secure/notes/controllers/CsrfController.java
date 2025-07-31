package com.secure.notes.controllers;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CsrfController {
    @GetMapping("/api/csrf-token")
    public CsrfToken csrfToken(HttpServletRequest request) {
        // 從請求屬性中取得 Spring Security 自動生成的 CsrfToken 物件並回傳
        return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    }
}
