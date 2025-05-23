package com.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/scope")
public class ScopeProtectedController {

    @GetMapping("/read")
    @PreAuthorize("hasAnyAuthority('SCOPE_read')")
    public String read() {
        return "You have READ access.";
    }

    @PostMapping("/write")
    @PreAuthorize("hasAnyAuthority('SCOPE_write')")
    public String write() {
        return "You have WRITE access.";
    }

    @DeleteMapping("/delete")
    @PreAuthorize("hasAnyAuthority('SCOPE_delete')")
    public String delete() {
        return "You have DELETE access.";
    }

    @GetMapping("/whoami")
    @PreAuthorize("hasAuthority('SCOPE_delete')")
    public Map<String, Object> whoami(@AuthenticationPrincipal Jwt jwt){
        return Map.of(
                "subject", jwt.getSubject(),
                "scopes", jwt.getClaimAsString("scope"),
                "claims", jwt.getClaims()
        );
    }
}
