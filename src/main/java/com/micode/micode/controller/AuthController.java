package com.micode.micode.controller;

import com.micode.micode.dto.*;
import com.micode.micode.model.RefreshToken;
import com.micode.micode.model.User;
import com.micode.micode.security.JwtService;
import com.micode.micode.service.RefreshTokenService;
import com.micode.micode.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    @PostMapping("/register")
    public RegisterResponse register(@Valid @RequestBody RegisterRequest registerRequest, HttpServletRequest httpRequest) {
        // --- Récupération de l'IP réelle ( compatible proxy / nginx )
        String clientIp = httpRequest.getHeader("X-Forwarded-For");
        if (clientIp == null) {
            clientIp = httpRequest.getRemoteAddr();
        }
        return userService.register(registerRequest, clientIp);
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest httpRequest) {
        String clientIp = httpRequest.getHeader("X-Forwarded-For");
        if (clientIp == null) {
            clientIp = httpRequest.getRemoteAddr();
        }
        return userService.login(loginRequest, clientIp);
    }

    @GetMapping("/me")
    public RegisterResponse me(Authentication authentication) {
        String email = authentication.getName();
        var user = userService.findByEmail(email);

        return new RegisterResponse(
                "User authenticated",
                user.getEmail(),
                user.getUsername()
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refreshToken(@RequestBody RefreshRequest request) {

        if (request.getRefreshToken() == null || request.getRefreshToken().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Refresh token is required");
        }

        String requestToken = request.getRefreshToken();

        RefreshToken refreshToken = refreshTokenService.findByToken(requestToken)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Invalid refresh token"
                ));

        refreshTokenService.verifyExpiration(refreshToken);

        refreshTokenService.delete(refreshToken);

        String newAccessToken = jwtService.generateToken(refreshToken.getUser().getEmail());

        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(refreshToken.getUser());

        return ResponseEntity.ok(
                new RefreshResponse(
                        newAccessToken,
                        newRefreshToken.getToken()
                )
        );
    }

    @PostMapping("/logout")

    public ResponseEntity<String> logout(Authentication authentication) {

        if (authentication == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not authenticated");

        }

        String email = authentication.getName();
        User user = userService.findByEmail(email);

        refreshTokenService.deleteByUser(user);

        return ResponseEntity.ok("Logged out successfully");
    }
}
