package com.example.props;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "custom.oauth2")
@Getter
@Setter
public class OAuth2ClientProperties {
    private String redirectUri;
    private List<String> scopes = new ArrayList<>();
}
