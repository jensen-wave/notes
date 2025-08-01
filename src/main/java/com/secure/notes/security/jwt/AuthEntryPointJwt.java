package com.yourpackage.security.jwt; // 請替換成您的專案套件路徑

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 此類別用於自訂處理未經授權 (Unauthorized) 的請求。
 * 當使用者嘗試存取需要驗證的資源，但未提供或提供了無效的憑證時，
 * Spring Security 會觸發此進入點 (Entry Point)。
 */
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    /**
     * 這個方法會在偵測到未經授權的請求時被呼叫。
     *
     * @param request       傳入的 HTTP 請求。
     * @param response      準備回傳的 HTTP 回應。
     * @param authException 觸發此方法的驗證例外。
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

        // 1. 記錄錯誤：使用 logger 記錄未授權的錯誤訊息，方便後續追蹤與除錯。
        logger.error("Unauthorized error: {}", authException.getMessage());

        // 2. 設定回應標頭 (Header)：
        //    - 將 Content-Type 設定為 application/json，告知客戶端回傳的是 JSON 格式的資料。
        //    - 將 HTTP 狀態碼設定為 401 (SC_UNAUTHORIZED)，表示請求缺乏有效的驗證憑證。
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // 3. 建立回應主體 (Body)：
        //    - 建立一個 Map 物件來存放要回傳給客戶端的錯誤資訊。
        //    - 包含狀態碼、錯誤類型、從例外中取得的詳細訊息以及請求的路徑。
        final Map<String, Object> body = new HashMap<>();
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", authException.getMessage());
        body.put("path", request.getServletPath());

        // 4. 轉換為 JSON 並寫入回應：
        //    - 建立 ObjectMapper 物件，這是 Jackson 函式庫的核心，用來在 Java 物件和 JSON 之間進行轉換。
        //    - 使用 writeValue 方法將 body 這個 Map 物件轉換成 JSON 字串，並直接寫入到回應的輸出流 (Output Stream) 中。
        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }
}
