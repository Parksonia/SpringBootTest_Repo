package com.example.sanchecktest.service;

import com.example.sanchecktest.domain.RefreshToken;
import com.example.sanchecktest.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshToken findByRefreshToken(String refreshToken) {

     return refreshTokenRepository.findByRefreshToken(refreshToken)  //리프레시 토큰으로 리프레시 토큰 객체를 검색하여 전달
             .orElseThrow(() -> new IllegalArgumentException("Unexpected token"));


    }
}
