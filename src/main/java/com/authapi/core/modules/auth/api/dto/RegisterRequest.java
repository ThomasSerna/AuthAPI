package com.authapi.core.modules.auth.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @NotBlank(message = "Email is required.")
    @Email(message = "Email must be valid.")
    String email,

    @NotBlank(message = "Password is required.")
    @Size(max = 72, message = "Password must be at most 72 characters.")
    String password,

    @NotBlank(message = "Full name is required.")
    @Size(max = 255, message = "Full name must be at most 255 characters.")
    String fullName
) {
}
