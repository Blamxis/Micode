package com.micode.micode.service;

import com.micode.micode.dto.LoginResponse;
import com.micode.micode.dto.LoginRequest;
import com.micode.micode.dto.RegisterRequest;
import com.micode.micode.dto.RegisterResponse;
import com.micode.micode.exception.EmailAlreadyUsedException;
import com.micode.micode.exception.RoleNotFoundException;
import com.micode.micode.model.Role;
import com.micode.micode.model.User;
import com.micode.micode.repository.RoleRepository;
import com.micode.micode.repository.UserRepository;
import com.micode.micode.security.JwtService;
import com.micode.micode.security.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RateLimiterService rateLimiterService;
    private final JwtService jwtService;

    public RegisterResponse register(RegisterRequest request, String clientIp) {

        if (!rateLimiterService.isAllowed(clientIp)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many requests, slow down");
        }

        // --- Normalisation de l'email ---
        String email = request.getEmail();

        // --- Retrait des espaces au début et à la fin ---
        email = email.trim();

        // --- Mettre en minuscule ---
        email = email.toLowerCase();

        // --- Empêcher les espaces dans l'email ---
        if (email.contains(" ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot contain spaces");
        }

        // --- Retour de l'email normalisé dans la request ---
        request.setEmail(email);

        // --- Validation simple du username ---
        String username = request.getUsername();

        // --- Retrait des espaces au début et à la fin ---
        username = username.trim();

        // Empêcher les espaces dans le username ---
        if (username.contains(" ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username cannot contain spaces");
        }

        // --- Empêcher les caractères dangereux ( anti - XSS ) ---
        if (username.contains("<") || username.contains(">")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid characters in username");
        }

        // --- Empêcher username trop court ---
        if (username.length() < 3) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username too short");
        }

        // --- Validation avancée du username ---
        if (!username.matches("^[a-zA-Z0-9._-]{3,20}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid username format");
        }

        // --- Retour de username nettoyé dans la request ---
        request.setUsername(username);


        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());
        if (existingUser.isPresent()) {
            throw new EmailAlreadyUsedException("Email already in use");
        }

        // --- Validation simple du mot de passe ---
        String password = request.getPassword();

        // --- Empêcher les mots de passe trop courts ---
        if (password.length() < 8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password too weak ( minimum 8 characters allowed)");
        }

        // --- Validation avancée du mot de passe ---
        if (!password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&._-]).{8,}$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number and 1 special character"
            );
        }

        String encodedPassword = passwordEncoder.encode(request.getPassword());

        Role role = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RoleNotFoundException("Default role USER not found"));

        User user = new User();

        user.setEmail(request.getEmail());
        user.setPassword(encodedPassword);
        user.setUsername(request.getUsername());

        Set<Role> roles = new HashSet<>();
        roles.add(role);
        user.setRoles(roles);

        try {
            Thread.sleep(300);
        } catch (InterruptedException ignored) {}

        userRepository.save(user);

        log.info("New user registered: {}", user.getEmail());

        return new RegisterResponse(
                "User registered successfully",
                user.getEmail(),
                user.getUsername()
        );
    }

    public LoginResponse login(LoginRequest request, String clientIp) {

        if (!rateLimiterService.isAllowed(clientIp)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many requests, slow down");
        }

        String email = request.getEmail();
        if (email == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is required");
        }

        email = email.trim().toLowerCase();

        if (email.contains(" ")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email cannot contain spaces");
        }

        if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email format");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid email or password"
                ));

        String password = request.getPassword();
        if (password == null || password.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is required");
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.UNAUTHORIZED,
                    "Invalid email or password"
            );
        }

        try {
            Thread.sleep(200);
        } catch (InterruptedException ignored) {}

        String token = jwtService.generateToken(email);

        log.info("User logged in: {}", email);

        return new LoginResponse(
                "Login successful",
                token,
                user.getEmail(),
                user.getUsername()
        );
    }
}
