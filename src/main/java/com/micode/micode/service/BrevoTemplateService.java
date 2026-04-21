package com.micode.micode.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

@Service
public class BrevoTemplateService {

    @Value("${brevo.api.key}")
    private String apiKey;

    private final WebClient webClient = WebClient.builder()
            .baseUrl("https://api.brevo.com/v3")
            .build();

    public void sendVerificationEmail(String to, String link, int templateId) {

        Map<String, Object> body = Map.of(
                "to", new Object[]{ Map.of("email", to) },
                "templateId", templateId,
                "params", Map.of("link", link)
        );

        webClient.post()
                .uri("/smtp/email")
                .header("api-key", apiKey)
                .header("Content-Type", "application/json")
                .bodyValue(body)
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }
}
