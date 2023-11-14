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
        return userRepository.save(User.builder().email(addUserDTO.getEmail())
                .password(bCryptPasswordEncoder.encode(addUserDTO.getPassword()))
                .build()).getId();
    }

}
