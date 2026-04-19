package com.authapi.core.modules.auth.domain.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.RefreshToken;

public interface RefreshTokenRepository {

    int revokeIfActive(UUID id, String tokenHash, Instant revokedAt, Instant now);

    int revokeActiveTokensForUser(UUID userId, Instant revokedAt, Instant now);

    Optional<RefreshToken> findByIdAndTokenHash(UUID id, String tokenHash);

    RefreshToken save(RefreshToken token);

    RefreshToken saveAndFlush(RefreshToken token);
}
