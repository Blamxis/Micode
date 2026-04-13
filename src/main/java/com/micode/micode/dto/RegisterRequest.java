package com.micode.micode.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder

public class RegisterRequest {
    private String email;
    private String username;
    private String password;
}
