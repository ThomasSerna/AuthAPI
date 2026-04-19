package com.authapi.core.modules.auth.domain.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.PasswordResetToken;

public interface PasswordResetTokenRepository {

    Optional<PasswordResetToken> findByIdAndTokenHash(UUID id, String tokenHash);

    int invalidateActiveTokensForUser(UUID userId, Instant consumedAt, Instant now);

    PasswordResetToken saveAndFlush(PasswordResetToken token);
}
