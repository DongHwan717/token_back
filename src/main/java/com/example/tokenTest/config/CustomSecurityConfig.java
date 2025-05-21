package com.example.tokenTest.config;

import com.example.tokenTest.member.security.filter.JWTCheckFilter;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Log4j2
public class CustomSecurityConfig {

    @Autowired
    private JWTCheckFilter jwtCheckFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.formLogin(httpSecurityFormLoginConfigurer -> {
            httpSecurityFormLoginConfigurer.disable();
        });

        // 토큰 방식이기 때문에 로그아웃 기능 필요없음
        httpSecurity.logout(config -> config.disable());
        // GET 방식을 제외한 모든 요청에 CSRF 토근인 것을 포함시키는 설정
        httpSecurity.csrf(config -> config.disable());
        // API 서버는 Session 생성이 필요 없음
        httpSecurity.sessionManagement(sessionManagementConfig -> {
            sessionManagementConfig.sessionCreationPolicy(SessionCreationPolicy.NEVER);
        });
        httpSecurity.authorizeHttpRequests((authz) -> {
            authz.anyRequest().permitAll();
        });

        //UsernamePasswordAuthenticationFilter.class 앞에 jwtCheckFilter 실행하도록 설정
        httpSecurity.addFilterBefore(jwtCheckFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
