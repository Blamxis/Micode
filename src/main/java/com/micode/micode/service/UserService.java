package com.micode.micode.service;

import com.micode.micode.dto.RegisterRequest;
import com.micode.micode.repository.RoleRepository;
import com.micode.micode.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor

public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public void register(RegisterRequest request) {}
}
