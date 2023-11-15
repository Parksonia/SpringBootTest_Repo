package com.example.sanchecktest.config;
import com.example.sanchecktest.service.UserDetailService;
import jakarta.servlet.DispatcherType;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@RequiredArgsConstructor  //생성자 생략 가능 의존성 자동 주입
@Configuration
@EnableWebSecurity(debug = true) // 운용 환경에서는 꼭 꺼야함
public class WebSecurityConfig {  // 실제 인증 처리를 하는 config.java

  private final UserDetailService userService;

    //스프링 시큐리티 기능 비활성화 - 정적 리소스(static 하위 img등의 resource),h2 console 하위 url에 설정
    @Bean
    public WebSecurityCustomizer configure() {
        return (web) -> web.ignoring()
            .requestMatchers(toH2Console())
            .requestMatchers(
                    new AntPathRequestMatcher("/img/**"),
                    new AntPathRequestMatcher("/css/**"),
                    new AntPathRequestMatcher("/js/**")
            );
}

    //특정 HTTP요청에 대한 웹기반 보안 구성
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


       return http
               .authorizeHttpRequests((authorizeHttpRequests)-> authorizeHttpRequests
                        .requestMatchers(new AntPathRequestMatcher("/**"),
                                         new AntPathRequestMatcher("/login")).permitAll())

               .formLogin(loginform -> loginform
                       .loginPage("/login")
                       .defaultSuccessUrl("/")
               )
               .logout(logout -> logout
                       .logoutSuccessUrl("/login")
                       .invalidateHttpSession(true)  //로그아웃하고 세션 정보 삭제 여부
               )
                .csrf(AbstractHttpConfigurer::disable)
               /*
                또 다른 방법
               .csrf((csrf) -> csrf
                        .ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**"))) csrf 비활성화 csrf토큰 불필요 */
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



/*
    //인증 관리자 설정
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() throws Exception {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();

        daoAuthenticationProvider.setUserDetailsService(userService);
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());

        return daoAuthenticationProvider;
    }
*/



    //패스워드 인코더로 사용할 빈 등록
    @Bean
  public BCryptPasswordEncoder bCryptPasswordEncoder() {
      return new BCryptPasswordEncoder();
    }

}
