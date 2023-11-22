package com.example.sanchecktest.config.jwt;

import com.example.sanchecktest.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

@RequiredArgsConstructor
@Service
public class TokenProvider {

    private final JwtProperties jwtProperties; //properties 객체 정보

    public String generateToken(User user, Duration expiredAt) {
        Date now = new Date();
      return makeToken(new Date(now.getTime() + expiredAt.toMillis()),user);

    }
    //JWT 토큰 생성 메서드
    private String makeToken(Date expiry, User user) { // 만료시간,유저정보를 인자로 받음
    Date now = new Date();

    return Jwts.builder()
            .setHeaderParam(Header.TYPE,Header.JWT_TYPE) //헤더- 타입: JWT
            .setIssuer(jwtProperties.getIssuer()) //내용-iss: sonia.sy1992@gmail.com
            .setIssuedAt(now) //내용-iat: 현재시간
            .setExpiration(expiry) //내용 -exp: expiry 변수값
            .setSubject(user.getEmail())  //내용-sub : 'subjectValue'는 도메인 내 사용자의 고유 식별자 email
            .claim("id",user.getId()) //클레임-id :유저id
            //서명 : 비밀값과 함께 해시값을 HS256 방식으로 암호화
            .signWith(SignatureAlgorithm.HS256,jwtProperties.getSecretKey())
            .compact();

    }
    //JWT 토큰 유효성 검증 메서드
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(jwtProperties.getSecretKey()) //비밀값으로 복호화
                    .parseClaimsJws(token);
            return  true;
        }catch (Exception e) { //복호화 과정에서 에러가 나면 유효하지 않은 토큰
            return false;
        }
    }
    // 인증정보를 담은 객체 반환 -토큰 기반으로 인증 정보를 가져오는 메서드
    public Authentication getAuthentication(String token) {

        Claims claims = getClaims(token); //비밀값으로 복호화 하여 클레임을 가져오는 private메서드 호출, 클레임 정보를 반환
        Set<SimpleGrantedAuthority> authorities = Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"));

        return new UsernamePasswordAuthenticationToken(new org.springframework.security.core.userdetails.User( //주의 User는 스프링 시큐리티 제공객체인 User를 임포트 해야함
                claims.getSubject(),"",authorities),token,authorities); //user_id담은 토큰제목과 토큰기반으로 인증정보를 담아 Authentication의 구현체 반환
    }


    public Long getUserId(String token) { //토큰 기반으로 사용자id를 가져오는 메서드
        Claims claims =getClaims(token);
        return claims.get("id",Long.class); //클레임에서 id로 저장된 값을 반환
    }
    private Claims getClaims(String token) {
    return Jwts.parser()
            .setSigningKey(jwtProperties.getSecretKey())
            .parseClaimsJws(token)
            .getBody();
    }

}