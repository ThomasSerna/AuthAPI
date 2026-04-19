package com.authapi.core.modules.auth.api.dto;

import jakarta.validation.constraints.NotBlank;

public record ConfirmEmailVerificationRequest(
    @NotBlank(message = "Token is required.")
    String token
) {
}
