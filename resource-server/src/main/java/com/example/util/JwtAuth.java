package com.example.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Component
public class JwtAuth {

    public boolean hasRole(Authentication authentication, String role) {
        if(authentication.getPrincipal() instanceof Jwt jwt) {
            String claim = jwt.getClaimAsString("role");
            return claim != null && claim.equals(role);
        }
        return false;
    }
}
