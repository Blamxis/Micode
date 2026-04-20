package com.micode.micode.service;

import com.micode.micode.dto.ChangePasswordRequest;
import com.micode.micode.dto.LoginRequest;
import com.micode.micode.dto.LoginResponse;
import com.micode.micode.model.RefreshToken;
import com.micode.micode.model.User;
import com.micode.micode.repository.UserRepository;
import com.micode.micode.security.JwtService;
import com.micode.micode.security.RateLimiterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RateLimiterService rateLimiterService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Override
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

        if (!user.isEmailVerified()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Email not verified");
        }

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

        String accessToken = jwtService.generateToken(email);

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        log.info("User logged in: {}", email);

        return new LoginResponse(
                "Login successful",
                accessToken,
                refreshToken.getToken(),
                user.getEmail(),
                user.getUsername()
        );
    }

    @Override
    public void logout(User user) {
        refreshTokenService.deleteByUser(user);
    }

    @Override
    public void changePassword(String email, ChangePasswordRequest request) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Current password is incorrect");
        }

        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "New password must be different from the current password"
            );
        }

        String newPassword = request.getNewPassword();

        if (newPassword.length() < 8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password too weak (minimum 8 characters)");
        }

        if (!newPassword.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&._-]).{8,}$")) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Password must contain at least 1 uppercase, 1 lowercase, 1 number and 1 special character"
            );
        }

        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);

        userRepository.save(user);

        refreshTokenService.deleteByUser(user);
    }

    @Override
    public User findByEmail(String email) {
            return userRepository.findByEmail(email)
                    .orElseThrow(() -> new ResponseStatusException(
                            HttpStatus.NOT_FOUND,
                            "User not found"
                    ));
    }
}
