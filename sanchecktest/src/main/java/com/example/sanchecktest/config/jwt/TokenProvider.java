package com.example.sanchecktest.config.jwt;

import com.example.sanchecktest.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class TokenProvider {

    private final JwtProperties jwtProperties;

    public String getnerateToken(User user, Duration expiredAt) {

        Date now = new Date();
        return makeToken(new Date(now.getTime() + expiredAt.toMillis()),user);
    }

    //토큰 생성 메서드, 파라미터로 만료시간과 유저정보를 받음
    private String makeToken(Date expiry,User user) {
        Date now = new Date();

        return Jwts.builder()
                .setHeaderParam(Header.TYPE,Header.JWT_TYPE)//headertype:JWT
                .setIssuer(jwtProperties.getIssuer())//내용:jwt.properties에서 설정한 값(sonia.sy1992@gmail.com)
                .setIssuedAt(now) //내용: 현재시간
                .setExpiration(expiry) //내용 :expiry 멤버 변수 값
                .setSubject(user.getEmail()) //내용 : 유저 이메일
                .claim("id",user.getId())  //클레임 id : 유저ID
                //서명 : jwt.properites secret_key 비밀값 과 함께  해시값을 HS256 방식으로 암호화
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getSecretKey())
                .compact();

    }
    //토큰이 유효한 지 검사하는 메서드
    public boolean validToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretKey()) //비밀값으로 복호화
                    .parseClaimsJws(token);
            return true; // 유효
        }catch (Exception e) {
            return false;  //복호화 과정에서 에러가 난다면 유효하지 않은 토큰임

        }

    }
    //토큰 기반으로 인증 정보를 가져오는 메서드
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"));

        return new UsernamePasswordAuthenticationToken(new org.springframework.security.core.userdetails.User(claims.getSubject(),"",authorities),token,authorities);
    }

    private Claims getClaims(String token) {

    return Jwts.parser() //클레임 조회
            .setSigningKey(jwtProperties.getSecretKey())
            .parseClaimsJwt(token)
            .getBody();
    }

}
