package com.micode.micode.service;

import com.micode.micode.dto.ChangePasswordRequest;
import com.micode.micode.dto.LoginRequest;
import com.micode.micode.dto.LoginResponse;
import com.micode.micode.model.User;

public interface AuthService {

    LoginResponse login(LoginRequest request, String clientIp);

    void logout(User user);

    void changePassword(String email, ChangePasswordRequest request);

    User findByEmail(String email);
}
