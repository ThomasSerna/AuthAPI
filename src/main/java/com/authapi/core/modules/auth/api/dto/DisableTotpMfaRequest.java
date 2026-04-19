package com.authapi.core.modules.auth.api.dto;

import jakarta.validation.constraints.NotBlank;

public record DisableTotpMfaRequest(
    @NotBlank(message = "Code is required.")
    String code
) {
}
