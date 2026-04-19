package com.authapi.core.modules.auth.domain.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.EmailVerificationToken;

public interface EmailVerificationTokenRepository {

    Optional<EmailVerificationToken> findByIdAndTokenHash(UUID id, String tokenHash);

    int invalidateActiveTokensForUser(UUID userId, Instant consumedAt, Instant now);

    EmailVerificationToken saveAndFlush(EmailVerificationToken token);
}
