package com.micode.micode.service;

import com.micode.micode.dto.RegisterRequest;
import com.micode.micode.dto.RegisterResponse;

public interface RegisterService {
    RegisterResponse register(RegisterRequest request, String clientIp);

    void resendVerificationEmail(String email);
}
