package com.example.sanchecktest.service;

import com.example.sanchecktest.domain.User;
import com.example.sanchecktest.dto.AddUserDTO;
import com.example.sanchecktest.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public Long save(AddUserDTO addUserDTO) {
        return userRepository.save(User.builder()
                .email(addUserDTO.getEmail())
             /*   .userid(addUserDTO.getUserid())*/
                .password(bCryptPasswordEncoder.encode(addUserDTO.getPassword()))
                .build()).getId();
    }


   // token 유저를 받아서 검색 후 리포지토리로 전달
    public User findById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Unexpected user"));

    }

    //OAuth email(유일값) 으로 로그인 처리하기 위한 메서드 추가
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(()->new IllegalArgumentException("Unexpected user"));
     }

}
