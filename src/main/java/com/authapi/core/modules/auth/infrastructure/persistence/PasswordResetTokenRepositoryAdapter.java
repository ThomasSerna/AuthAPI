package com.authapi.core.modules.auth.infrastructure.persistence;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import com.authapi.core.modules.auth.domain.model.PasswordResetToken;
import com.authapi.core.modules.auth.domain.repository.PasswordResetTokenRepository;

import org.springframework.stereotype.Repository;

@Repository
public class PasswordResetTokenRepositoryAdapter implements PasswordResetTokenRepository {

    private final JpaPasswordResetTokenRepository jpaPasswordResetTokenRepository;

    public PasswordResetTokenRepositoryAdapter(JpaPasswordResetTokenRepository jpaPasswordResetTokenRepository) {
        this.jpaPasswordResetTokenRepository = jpaPasswordResetTokenRepository;
    }

    @Override
    public Optional<PasswordResetToken> findByIdAndTokenHash(UUID id, String tokenHash) {
        return jpaPasswordResetTokenRepository.findByIdAndTokenHash(id, tokenHash);
    }

    @Override
    public int invalidateActiveTokensForUser(UUID userId, Instant consumedAt, Instant now) {
        return jpaPasswordResetTokenRepository.invalidateActiveTokensForUser(userId, consumedAt, now);
    }

    @Override
    public PasswordResetToken saveAndFlush(PasswordResetToken token) {
        return jpaPasswordResetTokenRepository.saveAndFlush(token);
    }
}
