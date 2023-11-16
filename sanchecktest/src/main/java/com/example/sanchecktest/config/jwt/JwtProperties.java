package com.example.sanchecktest.config.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.service.annotation.GetExchange;

@Setter
@Getter
@Component
@ConfigurationProperties("jwt") // .properties에 값을 가져와서 객체로 사용할 수 있는 어노테이션
public class JwtProperties {

        private String issuer;
        private String secretKey;


}
