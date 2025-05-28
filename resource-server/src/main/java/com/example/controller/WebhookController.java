package com.example.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

@RestController
@RequestMapping("/webhook")
public class WebhookController {
    Logger logger = LoggerFactory.getLogger(WebhookController.class);
    @Value("${webhook.secret}")
    private String webhookSecret;

    @PostMapping
    public Mono<ResponseEntity<String>> handleWebhook(@RequestBody String payload,
                                                      @RequestHeader("X-Signature") String signature) {
        String computedSignature = hmacSha256(payload, webhookSecret);
        logger.info("Computed signature: " + computedSignature);
        if(computedSignature.equals(signature)) {
            logger.info("✅ Webhook verified: " + payload);
            return Mono.just(ResponseEntity.ok("Webhook received!"));
        } else {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("❌ Invalid signature"));
        }
    }

    private String hmacSha256(String payload, String secret) {
        logger.info("Computing HMAC for payload: " + payload);
        try {
            Mac hmacSha256= Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmacSha256.init(keySpec);
            byte[] rawHmac = hmacSha256.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute HMAC", e);
        }
    }
}
