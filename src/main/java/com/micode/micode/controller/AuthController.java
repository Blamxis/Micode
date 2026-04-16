package com.micode.micode.controller;

import com.micode.micode.dto.LoginRequest;
import com.micode.micode.dto.LoginResponse;
import com.micode.micode.dto.RegisterRequest;
import com.micode.micode.dto.RegisterResponse;
import com.micode.micode.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    private final UserService userService;

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
}
