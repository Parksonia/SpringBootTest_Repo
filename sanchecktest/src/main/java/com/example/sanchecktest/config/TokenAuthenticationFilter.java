package com.example.sanchecktest.config;

import com.example.sanchecktest.config.jwt.TokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenProvider tokenProvider;
    private final static String HEADER_AUTHORIZATION = "Authorization";
    private final static String TOKEN_PREFIX ="Bearer";

   //OncePerRequestFilter 필수 메서드 오버라이드됨.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //요청 헤더의 Authorization 키의 값 조회
        String authorizationHeader = request.getHeader(HEADER_AUTHORIZATION);

        //가져온 값에서 접두사 제거
        String token = getAccessToekn(authorizationHeader);

        //가져온 토큰이 유효한지 확인하고, 유효한 떄는 인증 정보를 설정
        if(tokenProvider.validateToken(token)) {  //유효한가?
            Authentication authentication = tokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication); //유효한 정보를 담은 인증 객체 설정
        }
        filterChain.doFilter(request,response);
    }

    //접두사(Bearer)제거 메서드
    private String getAccessToekn(String authorizationHeader) {
        if(authorizationHeader !=null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
            return authorizationHeader.substring(TOKEN_PREFIX.length());
        }
        return null;
    }
}
