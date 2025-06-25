package org.example.authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfig {

    /**
     * 配置授权服务器的安全过滤链
     * <p>
     * 此方法主要用于构建和配置授权服务器的安全过滤链它定义了如何对传入的HTTP请求进行安全检查，
     * 以确保只有经过身份验证和授权的用户才能访问授权服务器的功能
     *
     * @param http HttpSecurity实例，用于配置Web安全设置
     * @return 返回配置好的SecurityFilterChain实例，用于应用安全过滤
     * @throws Exception 配置过程中可能抛出的异常
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 应用OAuth2授权服务器的默认安全配置
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // 开启oidc
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        // 配置表单登录的默认设置
        return http.formLogin(Customizer.withDefaults()).build();
    }


    /**
     * 配置并返回一个客户端注册存储的Bean
     * 该Bean用于在内存中存储已注册的OAuth2客户端详细信息
     * 主要包括客户端ID、客户端密钥、认证方法、授权类型、重定向URI和作用域等信息
     *
     * @return RegisteredClientRepository 客户端注册存储的实例
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // 创建并配置一个RegisteredClient实例
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-app")
                .clientSecret("{noop}client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8081/login/oauth2/code/client-app")
                .redirectUri("http://127.0.0.1:8081/authorized")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        // 返回一个内存中的客户端注册存储实例，用于存储配置好的客户端信息
        return new InMemoryRegisteredClientRepository(client);
    }


    /**
     * 配置JWKSource Bean，用于提供JWT的公钥和私钥
     * 此方法主要用于初始化和配置一个JWKSource对象，该对象包含了一对RSA密钥（公钥和私钥）
     * 这对于JWT的签名和验证过程至关重要
     *
     * @param keyPair 一个包含RSA公钥和私钥的密钥对
     * @return 返回一个ImmutableJWKSet对象，包含生成的RSA密钥对
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(KeyPair keyPair) {
        // 从密钥对中提取RSA公钥和私钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // 创建一个RSAKey对象，包含公钥、私钥，并为其分配一个唯一的键ID
        // @formatter:off
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        // @formatter:on

        // 将RSAKey对象封装到一个JWKSet中，然后创建一个ImmutableJWKSet对象
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }


    /**
     * 配置JWT解码器
     * <p>
     * 该方法用于创建和配置一个JWT解码器，该解码器使用提供的密钥对中的公钥进行JWT的验证和解码
     * 主要解决如何验证和解析JWT令牌的问题，确保令牌合法并能提取出其中的信息
     *
     * @param keyPair 密钥对，包含公钥和私钥，这里使用其公钥来构建JWT解码器
     * @return 返回配置好的JwtDecoder实例，用于后续的JWT验证和解码操作
     */
    @Bean
    public JwtDecoder jwtDecoder(KeyPair keyPair) {
        // 使用提供的密钥对中的公钥来构建一个NimbusJwtDecoder实例
        // 这里选择RSAPublicKey是因为在JWT验证中通常使用RSA算法的公钥来验证令牌的签名
        return NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
    }


    /**
     * 生成RSA密钥对
     * <p>
     * 本方法使用RSA算法生成一个密钥对，包含公钥和私钥主要用于加密和解密 purposes.
     * 选择RSA算法是因为它在当前加密标准下既安全又高效.
     * 密钥长度设定为2048位，以确保安全性同时保持性能的可接受性.
     *
     * @return KeyPair对象，包含生成的RSA公钥和私钥
     * @throws IllegalStateException 如果密钥对生成过程中出现异常，抛出此异常
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            // 获取RSA算法的密钥对生成器实例
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            // 初始化密钥对生成器，指定密钥长度为2048位
            keyPairGenerator.initialize(2048);
            // 生成密钥对
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            // 如果生成密钥对过程中出现异常，抛出IllegalStateException
            throw new IllegalStateException(ex);
        }
        // 返回生成的密钥对
        return keyPair;
    }


    /**
     * 配置授权服务器的设置
     * <p>
     * 此方法定义了OAuth2授权服务器的配置参数
     * 主要包括设置授权服务器的Issuer URI，即标识授权服务器的统一资源定位符
     * <p>
     * http://localhost:8083/.well-known/openid-configuration 请求后
     * <p>
     * {
     * "issuer": "http://localhost:9000",
     * "authorization_endpoint": "http://localhost:9000/oauth2/authorize",
     * "device_authorization_endpoint": "http://localhost:9000/oauth2/device_authorization",
     * "token_endpoint": "http://localhost:9000/oauth2/token",
     * "token_endpoint_auth_methods_supported": [
     * "client_secret_basic",
     * "client_secret_post",
     * "client_secret_jwt",
     * "private_key_jwt"
     * ],
     * "jwks_uri": "http://localhost:9000/oauth2/jwks",
     * "userinfo_endpoint": "http://localhost:9000/userinfo",
     * "end_session_endpoint": "http://localhost:9000/connect/logout",
     * "response_types_supported": [
     * "code"
     * ],
     * "grant_types_supported": [
     * "authorization_code",
     * "client_credentials",
     * "refresh_token",
     * "urn:ietf:params:oauth:grant-type:device_code"
     * ],
     * "revocation_endpoint": "http://localhost:9000/oauth2/revoke",
     * "revocation_endpoint_auth_methods_supported": [
     * "client_secret_basic",
     * "client_secret_post",
     * "client_secret_jwt",
     * "private_key_jwt"
     * ],
     * "introspection_endpoint": "http://localhost:9000/oauth2/introspect",
     * "introspection_endpoint_auth_methods_supported": [
     * "client_secret_basic",
     * "client_secret_post",
     * "client_secret_jwt",
     * "private_key_jwt"
     * ],
     * "code_challenge_methods_supported": [
     * "S256"
     * ],
     * "subject_types_supported": [
     * "public"
     * ],
     * "id_token_signing_alg_values_supported": [
     * "RS256"
     * ],
     * "scopes_supported": [
     * "openid"
     * ],
     * "registration_endpoint": "http://localhost:9000/connect/register"
     * }
     *
     * @return AuthorizationServerSettings对象，包含了授权服务器的配置设置
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8083") // 设置授权服务器的Issuer URI
                .build();
    }
}
