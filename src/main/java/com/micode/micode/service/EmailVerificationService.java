package com.micode.micode.service;

import com.micode.micode.service.BrevoTemplateService;
import com.micode.micode.model.User;
import com.micode.micode.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final BrevoTemplateService brevoTemplateService;

    public void generateAndSendToken(User user) {
        String token = UUID.randomUUID().toString();

        user.setEmailVerificationToken(token);
        user.setEmailVerificationExpiresAt(LocalDateTime.now().plusHours(24));

        userRepository.save(user);

        String link = "http://localhost:8080/auth/verify-email?token=" + token;

        brevoTemplateService.sendVerificationEmail(
                user.getEmail(),
                link,
                1
        );
    }

    public void verifyEmail(String token) {
        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token"));

        if (user.getEmailVerificationExpiresAt().isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Token expired");
        }

        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationExpiresAt(null);
        userRepository.save(user);
    }
}
