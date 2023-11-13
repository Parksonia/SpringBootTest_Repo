package com.example.sanchecktest.config;
import com.example.sanchecktest.service.UserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
@RequiredArgsConstructor  //생성자 생략 가능 의존성 자동 주입
@Configuration
public class WebSecurityConfig {  // 실제 인증 처리를 하는 config.java

  private final UserDetailService userDetailService;

    //스프링 시큐리티 기능 비활성화 - 정적 리소스(static 하위 img등의 resource),h2 console 하위 url에 설정
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
                .requestMatchers("/static/**"); //static 하위 리소스

    }
    //특정 HTTP요청에 대한 웹기반 보안 구성
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http.build();
    }
}
