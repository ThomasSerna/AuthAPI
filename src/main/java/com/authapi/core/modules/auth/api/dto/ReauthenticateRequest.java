package com.authapi.core.modules.auth.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ReauthenticateRequest(
    @NotBlank(message = "Password is required.")
    @Size(max = 72, message = "Password must be at most 72 characters.")
    String password,

    String mfaCode
) {
}
