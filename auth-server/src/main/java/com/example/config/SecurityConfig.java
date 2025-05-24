package com.example.config;

import com.example.props.OAuth2ClientProperties;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;
import java.util.UUID;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${custom.oauth2.redirect-uri}")
    private String redirectUri;

    // 🔐 Filter chain for the Authorization Server (handles /oauth2/** and discovery endpoints)
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        http
                .securityMatcher("/.well-known/**", "/oauth2/**", "/login", "/logout")// This filter chain only applies to authorization server endpoints
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/.well-known/**").permitAll()         // ✅ make discovery endpoints public
                        .requestMatchers("/css/**", "/js/**", "/favicon.ico").permitAll()
                        .anyRequest().authenticated()                           // 🔒 require login for everything else (e.g., /oauth2/authorize)
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers("/oauth2/token")) // allow token exchange via POST
                .formLogin(Customizer.withDefaults())  //login UI for auth code flow
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

    /* Register a demo OAuth client with client_credentials grant type and 'read' scope
    * Register anotherOAuth client with authorization and refresh token grant type with
    *  'read' and 'openid' scope
    * */
    @Bean
    public RegisteredClientRepository registeredClientRepository(OAuth2ClientProperties props) {
        logger.info("Redirect URI: {}", redirectUri);
        //client credentials flow
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("demo-client")
                .clientSecret("{noop}demo-secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .build();

        //authorization code and refresh token flows
        RegisteredClient authCodeClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(props.getRedirectUri())
                .clientId("postman")
                .clientSecret(passwordEncoder().encode("postman"))
                .scope("read")
                .scope("openid")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSettings(ClientSettings.builder()
                    .requireAuthorizationConsent(false) //disables consent form temporarily
                    .build())
                .build();

        RegisteredClient frontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .clientId("frontend")
                .clientSecret(passwordEncoder().encode("frontend-secret"))//plain text
                .scopes(scopes -> scopes.addAll(props.getScopes()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false) //disables consent form temporarily
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(List.of(registeredClient, authCodeClient, frontendClient));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.setAllowedOrigins(List.of("http://localhost:8083"));
        config.setAllowedMethods(List.of("POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/oauth2/token", config);

        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }

    @Bean
    public UserDetailsService users(PasswordEncoder encoder) {
        UserDetails user = User.builder()
                .username("testuser")
                .password(encoder.encode("testpass"))
                .roles("USER")
                .build();
        UserDetails basicUser = User.builder()
                .username("basicuser")
                .password(encoder.encode("password"))
                .roles("USER")
                .build();
        UserDetails adminUser = User.builder()
                .username("adminuser")
                .password(encoder.encode("password"))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, basicUser, adminUser);
    }

    //Provide an RSA JWK (JSON Web Key) for signing JWT access tokens
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    //Customize the JWT to include the 'scope' claim based on authorized scopes
    // (this is needed by the resource server)
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            String username = context.getPrincipal().getName();
            if (context.getTokenType().getValue().equals("access_token")) {
                //restrict claims in the token for each user. should not contain all claims from the client
                if(username.equals("basicuser")) {
                    context.getClaims().claim("scope", "read");
                    context.getClaims().claim("role", "basic");
                    context.getClaims().claim("email", "mbasuh@gmail.com");
                    context.getClaims().claim("given_name", "User");
                    context.getClaims().claim("family_name", "Doe");
                    context.getClaims().claim("picture", "https://example.com/john-doe.jpg");
                    context.getClaims().claim("locale", "en-US");
                    context.getClaims().claim("zoneinfo", "Europe/Berlin");
                    context.getClaims().claim("address", "{\"street_address\":\"123 Main St\",\"locality\":\"Anytown\",\"region\":\"NC\",\"postal_code\":\"27617\",\"country\":\"US\"}");
                    context.getClaims().claim("phone_number", "+1 919-555-1234");
                }else if(username.equals("adminuser")) {
                    context.getClaims().claim("scope", "read write delete");
                    context.getClaims().claim("role", "admin");
                    context.getClaims().claim("email", "admin@gmail.com");
                    context.getClaims().claim("given_name", "Admin");
                    context.getClaims().claim("family_name", "Doe");
                    context.getClaims().claim("picture", "https://example.com/john-doe.jpg");
                    context.getClaims().claim("locale", "en-US");
                    context.getClaims().claim("zoneinfo", "Europe/Berlin");
                }else {
                    Set<String> scopes = context.getAuthorizedScopes();
                    //associate all claims from the client with the access token
                    context.getClaims().claim("scope", String.join(" ", scopes));
                }
            }
            if(context.getTokenType().getValue().equals("id_token")) {
                // These claims are visible in the frontend
                context.getClaims().claim("preferred_username", username);

                if (username.equals("adminuser")) {
                    context.getClaims().claim("email", "admin@example.com");
                    context.getClaims().claim("role", "admin");
                } else {
                    context.getClaims().claim("email", "user@example.com");
                    context.getClaims().claim("role", "basic");
                }
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

