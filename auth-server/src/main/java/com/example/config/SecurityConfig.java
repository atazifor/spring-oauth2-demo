package com.example.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 🔐 Filter chain for the Authorization Server (handles /oauth2/** and discovery endpoints)
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher("/.well-known/**", "/oauth2/**")// This filter chain only applies to authorization server endpoints
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()
                )// Allow all requests on these paths (auth/token discovery shouldn't be restricted)
                .csrf(AbstractHttpConfigurer::disable)// Disable login UI (we're using client_credentials, not browser login)
                .formLogin(AbstractHttpConfigurer::disable)// Disable login UI (we're using client_credentials, not browser login)
                .exceptionHandling(ex -> ex // Instead of redirecting to login, return 401 for unauthorized requests
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .with(// Enable and configure all OAuth2 Authorization Server endpoints
                        authorizationServerConfigurer, config -> config
                        .authorizationEndpoint(Customizer.withDefaults())      // /oauth2/authorize
                        .tokenEndpoint(Customizer.withDefaults())              // /oauth2/token
                        .clientAuthentication(Customizer.withDefaults())       // Basic/client_secret handling
                        .oidc(Customizer.withDefaults())                       // /.well-known/openid-configuration (optional)
                );

        return http.build();
    }

    // 🌐 Default fallback security filter chain (handles all other endpoints)
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())// All other routes require authentication
                .formLogin(Customizer.withDefaults()); // Enable form-based login UI for those routes (e.g., for admin panels)
        return http.build();
    }

    // Register a demo OAuth client with client_credentials grant type and 'read' scope
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                .clientSecret("{noop}demo-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    //Provide an RSA JWK (JSON Web Key) for signing JWT access tokens
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    //Customize the JWT to include the 'scope' claim based on authorized scopes (this is needed by the resource server)
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (context.getTokenType().getValue().equals("access_token")) {
                Set<String> scopes = context.getAuthorizedScopes();
                context.getClaims().claim("scope", String.join(" ", scopes));
            }
        };
    }

    // 🔐 Generate RSA key pair for signing JWTs
    private static RSAKey generateRsa() {
        KeyPair keyPair = generateKeyPair();
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    // 🛠️ Key pair generator helper
    private static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

