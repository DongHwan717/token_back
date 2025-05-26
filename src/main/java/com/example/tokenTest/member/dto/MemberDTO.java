package com.example.tokenTest.member.dto;

import com.example.tokenTest.member.entity.MemberEntity;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class MemberDTO {

    private Long mno;
    private String socialId;
    private String provider;
    private String email;
    private String nickname;
    private String role;

    private Long id;

    public void updateNickname(String nickname) {
        this.nickname = nickname;
    }

    public MemberDTO(MemberEntity memberEntity) {
        this.mno = memberEntity.getMno();
        this.socialId = memberEntity.getSocialId();
        this.provider = memberEntity.getProvider();
        this.email = memberEntity.getEmail();
        this.nickname = memberEntity.getNickname();
        this.role = memberEntity.getRole();
    }
}
