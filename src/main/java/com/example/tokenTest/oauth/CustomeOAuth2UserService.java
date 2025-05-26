package com.example.tokenTest.oauth;

import com.example.tokenTest.member.dto.MemberDTO;
import com.example.tokenTest.member.entity.MemberEntity;
import com.example.tokenTest.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.lang.reflect.Member;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Service
@Log4j2
@RequiredArgsConstructor
public class CustomeOAuth2UserService extends DefaultOAuth2UserService {

   private final MemberRepository memberRepository; // 사용자 정보를 DB에 저장하기 위한 Repository

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId(); // 'kakao', 'google'
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        Map<String, Object> attributes = oAuth2User.getAttributes();

        // OAuth2UserInfo 추상화 (카카오, 구글 등 Provider별로 다를 수 있는 사용자 정보를 통일된 형태로 가져옴)
        OAuth2UserInfo oauth2UserInfo = null;

        if ("kakao".equals(registrationId)) {
            oauth2UserInfo = new KakaoOAuth2UserInfo(attributes);
        } else if ("google".equals(registrationId)) {
            // oauth2UserInfo = new GoogleOAuth2UserInfo(attributes); // 구글도 있다면 구현
        } else {
            throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
        }

        // 우리 서비스의 사용자 정보 (DB 연동)
        String socialId = oauth2UserInfo.getId(); // 소셜 서비스의 고유 ID
        String email = oauth2UserInfo.getEmail();
        String nickname = oauth2UserInfo.getNickname();

        Optional<MemberEntity> memberOptional = memberRepository.findBySocialIdAndProvider(socialId);

        MemberEntity memberEntity;

        if (memberOptional.isEmpty()) {
            // 첫 로그인: 회원가입 처리

            memberEntity = MemberEntity.builder()
                    .socialId(socialId)
                    .provider(registrationId)
                    .email(email)
                    .nickname(nickname)
                    .role("ROLE_USER") // 기본 역할 부여
                    .build();

            memberRepository.save(memberEntity);
        } else {
            // 이미 가입된 회원: 정보 업데이트 (필요시)
            memberEntity = memberOptional.get();

            memberEntity.updateNickname(nickname); // 예시: 닉네임 변경 시 업데이트
            memberRepository.save(memberEntity);
        }

        // 스프링 시큐리티 Context에 저장될 OAuth2User 객체 반환
        // 우리는 DB에서 가져온 user 객체를 포함하여 사용할 수 있도록 커스텀 OAuth2User를 반환할 수 있습니다.
        // 여기서는 간단하게 DefaultOAuth2User를 반환하지만, 실제로는 CustomOAuth2User를 구현하여 user 객체를 담는 것이 좋습니다.
        return new DefaultOAuth2User(
                Collections.singletonList(() -> "ROLE_USER"), // 권한 설정 (여기서는 간단히 ROLE_USER)
                attributes, // 원본 OAuth2 attributes
                userNameAttributeName // 사용자 이름을 식별할 속성 (id)
        );
    }
}
