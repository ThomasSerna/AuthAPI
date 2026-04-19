package com.authapi.core.modules.auth.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ChangeEmailRequest(
    @NotBlank(message = "New email is required.")
    @Email(message = "New email must be valid.")
    String newEmail
) {
}
