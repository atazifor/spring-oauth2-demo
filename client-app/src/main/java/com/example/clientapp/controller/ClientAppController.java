package com.example.clientapp.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/client")
@RequiredArgsConstructor
public class ClientAppController {
    private final WebClient webClient;

    @GetMapping("/call-resource")
    public Mono<String> callResourceServer() {
        return webClient
                .get()
                .uri("http://resource-server:8181/api/sample")
                .retrieve()
                .bodyToMono(String.class);
    }
}
