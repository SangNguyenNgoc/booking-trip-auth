package org.example.authserver.configs;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.authserver.filters.MyCorsFilter;
import org.example.authserver.services.TokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final Environment environment;
    private final MyCorsFilter myCorsFilter;
    private final TokenService tokenService;
    //    @Value("${client.client-id:default}")
//    private String clientId;
    @Value("${client.settings.require-authorization-consent}")
    private Boolean requireAuthorizationConsent;
    @Value("${client.settings.require-proof-key}")
    private Boolean requireProofKey;
    @Value("${token.access-token-time-to-live}")
    private Integer accessTokenTimeToLive;
    @Value("${token.key-size}")
    private Integer keySize;
    @Value("${spring.security.oauth2.authorizationserver.issuer}")
    private String iss;

    @Value("${url.login-page-url}")
    private String loginPageUrl;

    @Value("${url.login-url}")
    private String loginUrl;


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<String> redirectUris = Binder.get(environment)
                .bind("client.redirect-uris", Bindable.listOf(String.class))
                .get();
        List<String> clientIds = Binder.get(environment)
                .bind("client.client-id", Bindable.listOf(String.class))
                .get();

        List<RegisteredClient> registeredClients = new ArrayList<>();

        for (String clientId : clientIds) {
            RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientId)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUris(uris -> uris.addAll(redirectUris))
                    .scope(OidcScopes.OPENID)
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(requireAuthorizationConsent)
                            .requireProofKey(requireProofKey)
                            .build())
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofDays(accessTokenTimeToLive))
                            .build())
                    .build();

            registeredClients.add(registeredClient);
        }

        return new InMemoryRegisteredClientRepository(registeredClients);

    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        KeyPair keyPair = generator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        return ((jwkSelector, context) -> jwkSelector.select(new JWKSet(rsaKey)));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .addFilterBefore(myCorsFilter, ChannelProcessingFilter.class);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        http.exceptionHandling(exception -> {
            exception.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint(loginPageUrl),
                    new MediaTypeRequestMatcher((MediaType.TEXT_HTML))
            );
        });
        http.oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .addFilterBefore(myCorsFilter, ChannelProcessingFilter.class);
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-ui.html").permitAll()
                .requestMatchers(
                        "/auth/**",
                        "/css/**",
                        "/fonts/**",
                        "/images/**",
                        "/js/**",
                        "/error"
                )
                .permitAll()
                .anyRequest().permitAll()
        );
        http.addFilterBefore(myCorsFilter, ChannelProcessingFilter.class)
                .formLogin(login -> login
                        .loginPage(loginPageUrl)
                        .loginProcessingUrl(loginUrl)
                        .permitAll());

        http.logout(logout -> logout
                .logoutUrl("/logout") // URL để xử lý yêu cầu logout
                .logoutSuccessHandler((request, response, authentication) -> {
                    String accessToken = request.getHeader("Authorization");
                    if (accessToken != null && accessToken.startsWith("Bearer ")) {
                        accessToken = accessToken.substring(7);  // Loại bỏ 'Bearer ' khỏi token
                        // Lưu access token vào Redis
                        tokenService.blacklistToken(accessToken);
                    }
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");

                    // Tạo message JSON
                    String jsonMessage = "{\"message\": \"Logged out successfully\"}";

                    // Ghi message vào response
                    response.getWriter().write(jsonMessage);
                })
                .invalidateHttpSession(true)  // Hủy session hiện tại
                .clearAuthentication(true)    // Xóa thông tin xác thực
        );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(HttpServletResponse httpServletResponse) {

        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claims((claims) -> {
                    Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities());
                    claims.put("scope", roles);
                    if (context.getRegisteredClient().getClientId().equals("admin-client")
                            && !roles.contains("ROLE_ADMIN")) {
                        try {
                            httpServletResponse.sendError(403);
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
            }
        };
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        JwtAuthenticationConverter authConverter = new JwtAuthenticationConverter();
        authConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return authConverter;
    }


}
