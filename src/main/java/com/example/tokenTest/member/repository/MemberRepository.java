package com.example.tokenTest.member.repository;

import com.example.tokenTest.member.entity.MemberEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<MemberEntity, String> {

    @Query("select p from MemberEntity p where p.socialId = :socialId")
    Optional<MemberEntity> findBySocialIdAndProvider(@Param("socialId") String socialId);
}
