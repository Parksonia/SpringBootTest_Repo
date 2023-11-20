package com.example.sanchecktest.service;

import com.example.sanchecktest.config.jwt.TokenProvider;
import com.example.sanchecktest.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;

@RequiredArgsConstructor
@Service
public class TokenService {

    private final TokenProvider tokenProvider;  //토큰 제공자
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    public String createNewAccessToken(String refreshToken) {
        //토큰 유효성 검사 실패 시 예외발생
        if(!tokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Unexpected token");
        }
        //유효 하다면 리프레시 토큰으로 사용자 id 찾기
        Long userId = refreshTokenService.findByRefreshToken(refreshToken).getUserId();
        User user = userService.findById(userId); //사용자id로 사용자 찾기
        return tokenProvider.generateToken(user, Duration.ofHours(2)); // 새로운 엑세스 토큰 생성
    }

}
