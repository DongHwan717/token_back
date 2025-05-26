package com.example.tokenTest.member.controller;

import com.example.tokenTest.member.dto.MemberDTO;
import com.example.tokenTest.member.security.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/token")
@Log4j2
@RequiredArgsConstructor
public class TokenController {

    private final JWTUtil jwtUtil;

    @PostMapping("/make")
    public ResponseEntity<Map<String, String>> makeToken(@RequestBody MemberDTO memberDTO) {

        log.info("make token............");
        log.info("member Info : " + memberDTO);

        String mid = memberDTO.getId().toString();

        Map<String, Object> dataMap = Map.of("mid", memberDTO.getId(), "role", "ROLE_ADMIN");

        String accessToken = jwtUtil.createToken(dataMap, 10);
        String refreshToekn = jwtUtil.createToken(Map.of("mid", mid), 60);

        log.info("accessToken : " + accessToken);
        log.info("refreshToken : " + refreshToekn);

        return ResponseEntity.ok(Map.of("accessToken", accessToken, "refreshToken", refreshToekn));
    }
}