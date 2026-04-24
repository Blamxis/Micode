package com.micode.micode.service;

public interface ResetPasswordService {

    void createResetToken(String email);

    void resetPassword(String token, String newPassword);
}
