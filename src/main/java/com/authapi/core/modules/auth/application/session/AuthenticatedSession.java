package com.authapi.core.modules.auth.application.session;

import java.time.Instant;

import com.authapi.core.modules.user.domain.model.User;

public record AuthenticatedSession(
    String tokenType,
    String accessToken,
    Instant accessTokenExpiresAt,
    String refreshToken,
    Instant refreshTokenExpiresAt,
    User user
) {
}
