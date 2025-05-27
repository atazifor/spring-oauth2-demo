package com.example.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsGlobalConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/oauth2/**")
                .allowedOrigins("http://localhost:8083")
                .allowedMethods("POST", "OPTIONS", "GET")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}
