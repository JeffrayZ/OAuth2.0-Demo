package org.example.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    /**
     * 配置Spring Security过滤链的Bean
     * 该方法定义了默认的安全过滤链，用于处理HTTP请求的安全配置
     *
     * @param http HttpSecurity实例，用于配置Web安全
     * @return 返回配置好的SecurityFilterChain实例
     * <p>
     * 优先级设置为2，以确保该过滤链按照预期的顺序被考虑
     */
    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // 配置请求授权规则
                .authorizeHttpRequests(authorize ->
                        authorize
                                .anyRequest().authenticated()
                )
                // 使用默认的表单登录配置
                .formLogin(Customizer.withDefaults());
        return http.build();
    }


    /**
     * 配置用户服务的Bean
     * 该方法在Spring框架中定义一个Bean，类型为UserDetailsService，用于提供用户详细信息的服务
     * 主要用于内存中存储用户信息，适用于开发或测试环境下的简单认证
     *
     * @return UserDetailsService 一个配置了用户详情的服务实例，用于处理用户认证相关请求
     */
    @Bean
    UserDetailsService users() {
        // 创建一个用户详情实例，用于配置用户信息
        // 这里使用了Spring Security的内置方式配置用户密码
        // 用户名配置为"user"，密码为"123456"，并赋予"USER"角色
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("123456")
                .roles("USER")
                .build();

        // 返回一个内存中的用户详情管理器实例，初始化时包含之前配置的用户信息
        // 该管理器主要用于在内存中管理用户详情，适用于简单的认证场景
        return new InMemoryUserDetailsManager(user);
    }

}
