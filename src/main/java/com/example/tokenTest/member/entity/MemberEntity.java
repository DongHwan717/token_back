package com.example.tokenTest.member.entity;

import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "tbl_member")
@Builder
public class MemberEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long mno;

    @Column(nullable = false)
    private String socialId;

    @Column
    private String provider;

    @Column
    private String email;

    @Column
    private String nickname;

    @Column
    private String role;

    @Column
    private Long id;

    @Column
    private String registrationId;

    public void updateNickname(String nickname) {
        this.nickname = nickname;
    }
}
