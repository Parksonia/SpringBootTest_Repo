package com.example.sanchecktest.config;
import com.example.sanchecktest.config.jwt.TokenProvider;
import com.example.sanchecktest.config.oauth.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.example.sanchecktest.config.oauth.OAuth2SuccessHandler;
import com.example.sanchecktest.config.oauth.OAuth2UserCustomService;
import com.example.sanchecktest.repository.RefreshTokenRepository;
import com.example.sanchecktest.service.UserDetailService;
import com.example.sanchecktest.service.UserService;
;
import lombok.RequiredArgsConstructor;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.PropertySource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;


import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;
import static org.springframework.security.config.Customizer.withDefaults;

@RequiredArgsConstructor  //생성자 생략 가능 의존성 자동 주입
@Configuration
@EnableWebSecurity // 스프링 시큐리티 활성화
@PropertySource("classpath:application.properties")
public class WebOAuthSecurityConfig {  // 실제 인증 처리를 하는 config.java

    private final UserDetailService userDetailService;
    private final OAuth2UserCustomService oAuth2UserCustomService;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;

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
                        // .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll() //!!!!컨트롤러에서 화면 파일명을 리턴해 화면을 바꾸는 경우 추가!!!!!!
                        .requestMatchers(new AntPathRequestMatcher("/**"),
                                new AntPathRequestMatcher("/login"),
                                new AntPathRequestMatcher("/signup")
                        ).permitAll())

                .formLogin(loginform -> loginform
                        .loginPage("/login")
                        .defaultSuccessUrl("/")
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login")
                        .invalidateHttpSession(true)  //로그아웃하고 세션 정보 삭제 여부
                )
                .csrf(AbstractHttpConfigurer::disable)
                /*  또 다른 방법
              .csrf((csrf) -> csrf
                       .ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**"))) csrf 비활성화 csrf토큰 불필요*/

                /*   .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //스프링 시큐리티가 생성하지도않고 기존것을 사용하지도 않음 , JWT 사용할 때 설정
                */
                /*WebOAuthSecurityConfig*/
                .oauth2Login(Customizer.withDefaults())
                .oauth2Client(Customizer.withDefaults())
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class) //헤더를 확인할 커스텀 필터
                .authorizeHttpRequests((authorizeHttpRequests)-> authorizeHttpRequests  //토큰 재발급 URL은 인증 없이 접근 가능하도록 설정
                        .requestMatchers( new AntPathRequestMatcher("/api/token")).permitAll()
                        .requestMatchers( new AntPathRequestMatcher("/api/**")).authenticated().anyRequest().permitAll()) //나머지 API URL은 인증필요

                .oauth2Login(oauth2 ->oauth2
                        .loginPage("/login")
                        //Authorization 요청과 관련된 상태 저장
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository()))
                        .successHandler(oAuth2SuccessHandler())
                        .userInfoEndpoint(userInfo ->userInfo
                                .userService(oAuth2UserCustomService))
                )
                .exceptionHandling(exception ->exception // /api로 시작하는 url인 경우 401 상태 코드를 반환하도록 예외 처리
                        .defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                new AntPathRequestMatcher("/api/**"))
                )
                .build();

    }
    //OAuth2 인증 성공 시 실행할 핸들러 설정
    @Bean
    public OAuth2SuccessHandler oAuth2SuccessHandler() {
        return new OAuth2SuccessHandler(tokenProvider,
                refreshTokenRepository,
                oAuth2AuthorizationRequestBasedOnCookieRepository(),
                userService);
    }

    //OAuth2에 필요한 정보를 세션이아닌 쿠키에저장 할 수 있도록 저장소를 설정.
    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    //헤더값을 확인하기 위한 커스텀 필터 추가하는 메서드
    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(tokenProvider);
    }


    //인증 관리자 설정
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder,UserDetailService userDetailService)
            throws Exception {

        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailService) //사용자 정보 서비스 설정
                .passwordEncoder(bCryptPasswordEncoder)
                .and()
                .build();
    }

/*
   //인증 관리자 설정
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() throws Exception {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();

        daoAuthenticationProvider.setUserDetailsService(userDetailService);
        daoAuthenticationProvider.setPasswordEncoder(bCryptPasswordEncoder());

        return daoAuthenticationProvider;
    }*/


    //패스워드 인코더로 사용할 빈 등록
    @Bean
    public static BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


/*  @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
    }

    private ClientRegistration googleClientRegistration() {
        return ClientRegistration.withRegistrationId("google")
                .clientId("google-client-id")
                .clientSecret("google-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("profile", "email")
                .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
                .tokenUri("https://www.googleapis.com/oauth2/v4/token")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .clientName("Google")
                .build();
    }*/
}