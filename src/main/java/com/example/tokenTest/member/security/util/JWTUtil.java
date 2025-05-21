package com.example.tokenTest.member.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {

    private static String key = "1234567890123456789012345678901234567890";

    public String createToken(Map<String, Object> valueMap, int min) {

        SecretKey key = null;

        try {
            key = Keys.hmacShaKeyFor(JWTUtil.key.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

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

        return Jwts.builder().header()
                .add("typ", "JWT")
                .add("alg", "HS256")
                .and()
                .issuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .expiration((Date.from(ZonedDateTime.now()
                        .plusMinutes(min).toInstant())))
                .claims(valueMap)
                .signWith(key)
                .compact();
    }

    public Map<String, Object> validateToken(String token) {
        SecretKey key = null;

        try{
            key = Keys.hmacShaKeyFor(JWTUtil.key.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        //JWT(JSON Web Token)의 페이로드(Payload)에 담긴 정보, 즉 클레임(Claims)들을 표현하고 관리하기 위한 인터페이스
        Claims claims = Jwts.parser().verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        log.info(claims);

        return claims;
    }
}