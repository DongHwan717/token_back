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