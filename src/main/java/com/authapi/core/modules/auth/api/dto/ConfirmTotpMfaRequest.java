package com.authapi.core.modules.auth.api.dto;

import jakarta.validation.constraints.NotBlank;

public record ConfirmTotpMfaRequest(
    @NotBlank(message = "Code is required.")
    String code
) {
}
