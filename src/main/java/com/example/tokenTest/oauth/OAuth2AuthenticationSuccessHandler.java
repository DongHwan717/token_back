package com.example.tokenTest.oauth;

import com.example.tokenTest.jwt.JwtTokenProvider;
import com.example.tokenTest.member.dto.MemberDTO;
import com.example.tokenTest.member.security.util.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.lang.reflect.Member;
import java.util.Map;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    //private final UserRepository userRepository; // 유저 정보 가져오기 위함 (예시)

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        // OAuth2User 객체에서 사용자 정보 추출
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        // CustomOAuth2UserService에서 DB에 저장한 사용자 정보 가져오기 (예시)
        // 실제로는 OAuth2UserInfo 인터페이스를 사용한 user 객체를 CustomOAuth2User에 담아서 가져오는 것이 좋습니다.
        String socialId = oAuth2User.getName(); // user-name-attribute (id)
        String provider = oAuth2User.getAttributes().get("provider") != null ? (String) oAuth2User.getAttributes().get("provider") : "kakao"; // 실제 provider를 가져오는 로직 필요

        /*
        // 사용자 정보를 바탕으로 우리 서비스의 DB에서 User 객체 조회
        Optional<MemberDTO> userOptional = userRepository.findBySocialIdAndProvider(socialId, provider);
        MemberDTO memberDTO = userOptional.orElseThrow(() -> new IllegalArgumentException("User not found: " + socialId)); // 예외 처리

        // 사용자 정보로 JWT 토큰 생성
        String jwtToken = jwtUtil.createToken(Map.of(memberDTO.getId().toString(), memberDTO.getRole()), 10);

        // 프론트엔드로 리다이렉트할 URL 생성
        // JWT 토큰을 쿼리 파라미터에 담아서 보냅니다. (보안 고려하여 쿠키 또는 다른 방식도 고려)
        String targetUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/oauth2/redirect") // 프론트엔드 로그인 성공 리다이렉트 URL
                .queryParam("token", jwtToken)
                .build().toUriString();

        // 최종 리다이렉트
        getRedirectStrategy().sendRedirect(request, response, targetUrl);

         */
    }

}
