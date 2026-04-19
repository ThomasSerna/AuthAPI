package com.authapi.core.modules.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
    @NotBlank(message = "Current password is required.")
    @Size(max = 72, message = "Current password must be at most 72 characters.")
    String currentPassword,

    @NotBlank(message = "New password is required.")
    @Size(max = 72, message = "New password must be at most 72 characters.")
    String newPassword
) {
}
