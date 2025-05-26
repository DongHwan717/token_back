# Token 발급
## TokenController
### jwtUtil.createToken 메소드로 토큰 발급
- 파라미터
    - Map : 사용자 정보(추가 정보)
    - int : 토큰 유효 시간(분)

## JWTUtil
### createToken 토큰 발급하는 메소드
``` Java
    key = Keys.hmacShaKeyFor(JWTUtil.key.getBytes("UTF-8"));
```

``` Java
    /*
    *   typ과 alg는 JWT의 헤더(Header)에 포함되는 중요한 표준 필드
    *   typ : JWT의 타입(Type) 을 나타낸다.
    *   alg : JWT의 서명(Signature) 또는 암호화(Encryption) 알고리즘을 지정
    *   and :
    *   issuedAt : 언제 생성되었는지 나타내는 표준 클레임, 토큰의 유효성을 판단하고 관리하는데 중요한 역할을 한다.
    *   expiration : 언제까지 유효한지를 나타내는 표준 클레임
    *   claims : 추가적인 정보를 페이로드에 담기 위해 사용된다.
    *   signWith : 헤더(Header)와 페이로드(Payload)를 결합한 내용을 특정 서명 알고리즘(Algorithm) 과 키(Key) 를 사용하여 암호화
    *   compact : 최종적으로 JWT(JSON Web Token)를 문자열 형태로 생성
    * */

    Jwts.builder().header()
                .add("typ", "JWT")
                .add("alg", "HS256")
                .and()
                .issuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .expiration((Date.from(ZonedDateTime.now()
                        .plusMinutes(min).toInstant())))
                .claims(valueMap)
                .signWith(key)
                .compact();
```
### validateToken 토큰 검증하는 메소드
``` Java
    key = Keys.hmacShaKeyFor(JWTUtil.key.getBytes("UTF-8"));

    //JWT(JSON Web Token)의 페이로드(Payload)에 담긴 정보, 즉 클레임(Claims)들을 표현하고 관리하기 위한 인터페이스
    Claims claims = Jwts.parser().verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .getPayload();
```

# 권한
## CustomSecurityConfig
``` Java
     /**
     *  스프링 시큐리티에서 컨트롤러의 특정한 경로에 접근 제한을 설정하는 방법
     *  1. HttpSecurity 타입의 객체를 이용한 직접 설정
     *  2. 클래스 선언부나 메서드 선언부에 직접 설정할 수 있는 어노테이션을 이용하는 방식
     * 
     *  @PreAuthorize("hasRole('ROLE_ADMIN')") 아래 코드는 해당 어노테이션이 해당한다.
     * */
    httpSecurity.authorizeHttpRequests((authz) -> {
                    authz.anyRequest().permitAll();
            });
```

## JWTCheckFilter
### shouldNotFilter
``` Java
    // 특정 조건에 해당되는 요청에 대해서는 현재 필터를 건너뛰도록(필터링하지 않도록) 지정하는 역할

    ///api/token/은 토큰 없어도 접근 가능하도록 설정
    if(request.getServletPath().startsWith("/api/token/")) {
        return true;
    }
```
### doFilterInternal
``` Java
    String headerStr =  request.getHeader("Authorization");

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
```
# SNS 로그인
## 공통
### CustomeSecurityConfig
``` Java
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
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
  }
```
### CustomeOAuth2UserService.java
``` Java
@Service
@Log4j2
@RequiredArgsConstructor
public class CustomeOAuth2UserService extends DefaultOAuth2UserService {
  @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
      OAuth2User oAuth2User = super.loadUser(userRequest);
      
      ...
      
      if ("kakao".equals(registrationId)) {
          oauth2UserInfo = new KakaoOAuth2UserInfo(attributes);
      } else if ("google".equals(registrationId)) {
          // oauth2UserInfo = new GoogleOAuth2UserInfo(attributes); // 구글도 있다면 구현
      } else {
          throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
      }
      
      return null;
    }
}
```

## 카카오
### KakaoOAuth2UserInfo.java
``` Java
public class KakaoOAuth2UserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes;

    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getId() {
        return getAttributes().get("id").toString();
    }

    ...
}
```
