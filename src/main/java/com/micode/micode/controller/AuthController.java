package com.micode.micode.controller;

import com.micode.micode.dto.RegisterRequest;
import com.micode.micode.service.UserService;
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
    public void register(@RequestBody RegisterRequest registerRequest) {}
}
