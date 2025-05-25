package com.example.tokenTest.member.dto;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class MemberDTO {

    private String socialId;
    private String provider;
    private String email;
    private String nickname;
    private String role;

    private Long id;

    public void updateNickname(String nickname) {
        this.nickname = nickname;
    }
}
