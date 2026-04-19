package com.authapi.core.modules.auth.api.dto;

import java.util.List;
import java.util.UUID;

import com.authapi.core.modules.user.domain.model.User;

public record MeResponse(
    UUID id,
    String email,
    String fullName,
    List<String> roles,
    boolean emailVerified,
    boolean totpMfaEnabled
) {

    public static MeResponse from(User user) {
        return new MeResponse(
            user.getId(),
            user.getEmail(),
            user.getFullName(),
            user.getRoles().stream().map(role -> role.getName()).sorted().toList(),
            user.isEmailVerified(),
            user.isTotpMfaEnabled()
        );
    }
}
