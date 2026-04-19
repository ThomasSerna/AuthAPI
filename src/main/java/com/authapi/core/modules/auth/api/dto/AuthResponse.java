package com.authapi.core.modules.auth.api.dto;

import java.time.Instant;

import com.authapi.core.modules.auth.application.session.AuthenticatedSession;

public record AuthResponse(
    String tokenType,
    String accessToken,
    Instant accessTokenExpiresAt,
    String refreshToken,
    Instant refreshTokenExpiresAt,
    MeResponse user
) {

    public static AuthResponse from(AuthenticatedSession session) {
        return new AuthResponse(
            session.tokenType(),
            session.accessToken(),
            session.accessTokenExpiresAt(),
            session.refreshToken(),
            session.refreshTokenExpiresAt(),
            MeResponse.from(session.user())
        );
    }
}
