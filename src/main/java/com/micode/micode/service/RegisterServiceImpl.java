package com.micode.micode.service;

import com.micode.micode.dto.RegisterRequest;
import com.micode.micode.dto.RegisterResponse;
import com.micode.micode.exception.EmailAlreadyUsedException;
import com.micode.micode.exception.RoleNotFoundException;
import com.micode.micode.model.Role;
import com.micode.micode.model.User;
import com.micode.micode.repository.RoleRepository;
import com.micode.micode.repository.UserRepository;
import com.micode.micode.security.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegisterServiceImpl implements RegisterService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RateLimiterService rateLimiterService;
    private final EmailVerificationService emailVerificationService;
    private final EmailService emailService;

    @Override
    public RegisterResponse register(RegisterRequest request, String clientIp) {

        if (!rateLimiterService.isAllowed(clientIp)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many requests, slow down");
        }

        String email = request.getEmail();
        email = email.trim().toLowerCase();

        if (email.contains(" ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot contain spaces");
        }

        request.setEmail(email);

        String username = request.getUsername();
        username = username.trim();

        if (username.contains(" ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username cannot contain spaces");
        }

        if (username.contains("<") || username.contains(">")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid characters in username");
        }

        if (username.length() < 3) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username too short");
        }

        if (!username.matches("^[a-zA-Z0-9._-]{3,20}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid username format");
        }

        request.setUsername(username);

        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());
        if (existingUser.isPresent()) {
            throw new EmailAlreadyUsedException("Email already in use");
        }

        String password = request.getPassword();

        if (password.length() < 8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password too weak (minimum 8 characters)");
        }

        if (!password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&._-]).{8,}$")) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number and 1 special character"
            );
        }

        String encodedPassword = passwordEncoder.encode(password);

        Role role = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RoleNotFoundException("Default role USER not found"));

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(encodedPassword);
        user.setUsername(request.getUsername());
        user.setEmailVerified(false);

        Set<Role> roles = new HashSet<>();
        roles.add(role);
        user.setRoles(roles);

        try {
            Thread.sleep(300);
        } catch (InterruptedException ignored) {}

        userRepository.save(user);

        emailVerificationService.generateAndSendToken(user);

        log.info("New user registered: {}", user.getEmail());

        return new RegisterResponse(
                "User registered successfully. Please check your email to verify your account.",
                user.getEmail(),
                user.getUsername()
        );
    }

    @Override
    public void resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.isEmailVerified()) {
            throw new RuntimeException("Email already verified");
        }

        String token = UUID.randomUUID().toString();
        user.setEmailVerificationToken(token);
        user.setEmailVerificationExpiresAt(LocalDateTime.now().plusHours(24));
        userRepository.save(user);

        String link = "http://localhost:8080/auth/verify-email?token=" + token;

        emailService.sendEmail(
                user.getEmail(),
                "Verify your email",
                "Click this link to verify your email:\n" + link
        );

        log.info("Verification email resent to: {}", email);
    }

}
