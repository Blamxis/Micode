package com.micode.micode.dto;

public record ResetPasswordRequest(String token, String newPassword) {
}
