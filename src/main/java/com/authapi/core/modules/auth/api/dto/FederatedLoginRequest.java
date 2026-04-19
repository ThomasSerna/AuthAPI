package com.authapi.core.modules.auth.api.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record FederatedLoginRequest(
    @JsonAlias("credential")
    @NotBlank(message = "ID token is required.")
    String idToken,

    @Size(max = 12, message = "MFA code must be at most 12 characters.")
    String mfaCode
) {
}
