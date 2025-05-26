package com.example.tokenTest.config;

import com.example.tokenTest.jwt.JwtTokenProvider;
import com.example.tokenTest.member.security.filter.JWTCheckFilter;
import com.example.tokenTest.oauth.CustomeOAuth2UserService;
import com.example.tokenTest.oauth.OAuth2AuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Log4j2
@EnableWebSecurity
@RequiredArgsConstructor    // Lombok을 사용하여 final 필드에 대한 생성자 자동 생성
public class CustomSecurityConfig {

    @Autowired
    private JWTCheckFilter jwtCheckFilter;

    private final CustomeOAuth2UserService customeOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final JwtTokenProvider jwtTokenProvider; // JWT 토큰 제공자 주입

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer.disable())
                .logout(config -> config.disable()) // 토큰 방식이기 때문에 로그아웃 기능 필요없음
                .csrf(config -> config.disable())   // GET 방식을 제외한 모든 요청에 CSRF 토근인 것을 포함시키는 설정
                .sessionManagement(sessionManagementConfig -> sessionManagementConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션을 사용하지 않음 (JWT 기반 인증)

                .authorizeHttpRequests(authz -> {
                    // 로그인 관련 URL, OAuth2 콜백 URL, 에러 페이지는 인증 없이 허용
                    authz
                    .requestMatchers("/", "/login**", "/oauth2/**", "/error", "/api/public/**").permitAll().anyRequest().authenticated(); // 그 외 모든 요청은 인증 필요
                })

                .oauth2Login(oauth2 -> {
                    oauth2
                        // 커스텀 로그인 페이지가 있다면 지정 (없으면 기본 로그인 페이지 사용), SPA에서는 이 페이지가 백엔드에 있을 필요는 없습니다.
                        //.loginPage("/login")
                        // 인가 요청을 보낼 기본 URL, (프론트엔드에서 이 URL로 리다이렉트)
                        .authorizationEndpoint(auth -> auth.baseUri("/oauth2/authorization"))
                        // OAuth2 Provider로부터 콜백을 받는 URL
                        .redirectionEndpoint(redirection -> redirection.baseUri("/login/oauth2/code/*"))
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customeOAuth2UserService) // CustomOAuth2UserService 등록
                        )
                        .successHandler(oAuth2AuthenticationSuccessHandler) // JWT 발행 및 리다이렉트를 처리할 커스텀 핸들러 등록
                        .failureUrl("/login-failure"); // 로그인 실패 시 리다이렉트될 URL
                })

                .addFilterBefore(jwtCheckFilter, UsernamePasswordAuthenticationFilter.class)    //UsernamePasswordAuthenticationFilter.class 앞에 jwtCheckFilter 실행하도록 설정
        ;

        return httpSecurity.build();
    }
}
