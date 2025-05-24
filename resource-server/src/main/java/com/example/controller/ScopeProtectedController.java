package com.example.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/scope")
public class ScopeProtectedController {

    @GetMapping("/read")
    public String read() {
        return "You have READ access.";
    }

    @PostMapping("/write")
    public String write() {
        return "You have WRITE access.";
    }

    @DeleteMapping("/delete")
    public String delete() {
        return "You have DELETE access.";
    }

    @GetMapping("/whoami")
    public Map<String, Object> whoami(@AuthenticationPrincipal Jwt jwt){
        return Map.of(
                "subject", jwt.getSubject(),
                "scopes", jwt.getClaimAsString("scope"),
                "claims", jwt.getClaims()
        );
    }

    @GetMapping("/admin-stats")
    public String onlyAdmins() {
        return "Only admins see this";
    }
}
