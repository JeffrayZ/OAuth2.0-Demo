package org.example.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class ResourceConfig {
    /**
     * 配置Security过滤链
     *
     * 此方法用于配置和构建Spring Security的过滤链它定义了如何处理 incoming请求的认证和授权
     * 特别地，这段代码配置了对所有请求都需要进行认证，并且设置了使用OAuth 2资源服务器的JWT认证方式
     *
     * @param http HttpSecurity实例，用于配置Web安全设置
     * @return SecurityFilterChain对象，代表配置好的安全过滤链
     * @throws Exception 配置过程中可能抛出的异常
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 配置请求授权规则
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                // 配置OAuth 2资源服务器的JWT认证
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
