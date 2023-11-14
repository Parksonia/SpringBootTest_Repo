package com.example.sanchecktest.config;
import com.example.sanchecktest.service.UserDetailService;
import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor  //생성자 생략 가능 의존성 자동 주입
@Configuration
public class WebSecurityConfig {  // 실제 인증 처리를 하는 config.java

  private final UserDetailService userService;

    //스프링 시큐리티 기능 비활성화 - 정적 리소스(static 하위 img등의 resource),h2 console 하위 url에 설정
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
                .requestMatchers("/static/**","/h2-console/**"); //static 하위 리소스

    }
    //특정 HTTP요청에 대한 웹기반 보안 구성
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .authorizeHttpRequests(request -> request.dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/reserveClick")).authenticated()
                        .requestMatchers(new AntPathRequestMatcher("/reservationStatus")).authenticated()
                        .requestMatchers(new AntPathRequestMatcher("/setting/user")).hasRole("USER").anyRequest().permitAll())
                .formLogin() //폼 기반 로그인 설정 (커스텀,,,?)
                .loginPage("/login")
                .defaultSuccessUrl("/hello")
                .and()
                .logout() //로그아웃설정
                .logoutSuccessUrl("/login")
                .invalidateHttpSession(true)  //로그아웃하고 세션 정보 삭제 여부
                .and()
                .csrf().disable() //csrf 비활성화
                .build();
    }

    //인증 관리자 설정
    @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder,UserDetailService userDetailService)
      throws Exception {

      return http.getSharedObject(AuthenticationManagerBuilder.class)
              .userDetailsService(userService) //사용자 정보 서비스 설정
              .passwordEncoder(bCryptPasswordEncoder)
              .and()
              .build();
    }
    //패스워드 인코더로 사용할 빈 등록
    @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
      return new BCryptPasswordEncoder();
    }

}
