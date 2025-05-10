package com.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class SampleController {
    @GetMapping("/sample")
    public Map<String, String> getSample() {
        return Map.of("message", "Hello World!");
    }
}
