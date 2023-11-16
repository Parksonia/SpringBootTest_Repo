package com.example.sanchecktest.repository;

import com.example.sanchecktest.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Long> {

  // Optional<User> findByEmail(String email); // email로(사용자를 식별할 수 있는 고유값인) 사용자 정보를 가져옴

   Optional<User>findByUserid(String userid);

    /*JPA는 메서드 규칙에 맞춰 선언하면 이름을 분석해 자동으로 쿼리를 생성해줌
    * from user where email = #{email}
    * */
}
