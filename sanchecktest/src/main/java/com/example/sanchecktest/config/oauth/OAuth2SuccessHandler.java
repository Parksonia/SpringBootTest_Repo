package com.example.sanchecktest.config.oauth;

import com.example.sanchecktest.config.jwt.TokenProvider;
import com.example.sanchecktest.repository.RefreshTokenRepository;
import com.example.sanchecktest.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.time.Duration;
@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public static final String REFRESH_TOKEN_COOKIE_NAME= "refresh_token";
    public static final Duration REFRESH_TOKEN_DURATION= Duration.ofDays(14);
    public static final Duration ACCESS_TOKEN_DURATION = Duration.ofDays(1);

    public static final  String REDIRECT_PATH ="/hello";

    private final TokenProvider tokenProvider;
    private  final RefreshTokenRepository refreshTokenRepository;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository auth2AuthorizationRequestBasedOnCookieRepository;
    private  final UserService userService;
}
