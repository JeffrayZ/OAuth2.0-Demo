package org.example.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ClientConfig {

    /**
     * 配置Security过滤链
     * <p>
     * 该方法用于配置Web安全，包括请求的授权和OAuth2登录的设置
     * 它定义了哪些请求可以被所有人访问，哪些请求需要身份验证
     * 同时，它还配置了OAuth2登录的_success_url_
     *
     * @param http 用于配置Web安全的HttpSecurity对象
     * @return 返回配置好的SecurityFilterChain对象
     * @throws Exception 配置过程中可能抛出的异常
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        // 配置哪些请求可以被所有人访问
                        .requestMatchers("/", "/index", "/index.html", "/css/**", "/js/**", "/login.html").permitAll()
                        // 其他所有请求都需要身份验证
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        // 配置OAuth2登录成功后的默认跳转页面
                        .defaultSuccessUrl("/index", false)
                );
        return http.build();
    }
}
