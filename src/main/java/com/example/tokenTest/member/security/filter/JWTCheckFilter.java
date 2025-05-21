package com.example.tokenTest.member.security.filter;

import com.example.tokenTest.member.security.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor    //final 필드 또는 @NonNull 어노테이션이 붙은 필드를 파라미터로 갖는 생성자를 자동으로 생성해주는 역할
@Log4j2
public class JWTCheckFilter extends OncePerRequestFilter {

    @Autowired
    private JWTUtil jwtUtil;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // 특정 조건에 해당되는 요청에 대해서는 현재 필터를 건너뛰도록(필터링하지 않도록) 지정하는 역할

        ///api/token/은 토큰 없어도 접근 가능하도록 설정
        if(request.getServletPath().startsWith("/api/token/")) {
            return true;
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info("JWTCheckFilter doFilter...........");

        String headerStr =  request.getHeader("Authorization");

        log.info("headerStr : " + headerStr);

        /**
         *  Bearer : 표준화된 인증 스키마(Authentication Scheme)를 명시, OAuth 2.0 표준을 따른다.
         * */
        if(headerStr == null || !headerStr.startsWith("Bearer ")) {
            handleException(response, new Exception("ACCESS TOKEN  NOT FOUND"));
            return;
        }

        String accessToken = headerStr.substring(7);

        try {
            Map<String, Object> tokenMap = jwtUtil.validateToken(accessToken);

            log.info("tokenMap : " + tokenMap);

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            handleException(response, e);
        }
    }

    private void handleException(HttpServletResponse response, Exception e) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
    }
}